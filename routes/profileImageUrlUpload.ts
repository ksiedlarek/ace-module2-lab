/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import fs from 'node:fs'
import dns from 'node:dns'
import { Readable } from 'node:stream'
import { finished } from 'node:stream/promises'
import { type Request, type Response, type NextFunction } from 'express'

import * as security from '../lib/insecurity'
import { UserModel } from '../models/user'
import * as utils from '../lib/utils'
import logger from '../lib/logger'

function isPrivateIPv4 (ip: string): boolean {
  const parts = ip.split('.').map(Number)
  if (parts.length !== 4 || parts.some(isNaN)) {
    return false
  }
  const [p0, p1, p2, p3] = parts
  if (p0 < 0 || p0 > 255 || p1 < 0 || p1 > 255 || p2 < 0 || p2 > 255 || p3 < 0 || p3 > 255) {
    return false
  }

  // 10.0.0.0/8
  if (p0 === 10) return true
  // 127.0.0.0/8
  if (p0 === 127) return true
  // 0.0.0.0/8
  if (p0 === 0) return true
  // 172.16.0.0/12
  if (p0 === 172 && p1 >= 16 && p1 <= 31) return true
  // 192.168.0.0/16
  if (p0 === 192 && p1 === 168) return true
  // 169.254.0.0/16
  if (p0 === 169 && p1 === 254) return true
  // 100.64.0.0/10 (Carrier-grade NAT)
  if (p0 === 100 && (p1 >= 64 && p1 <= 127)) return true
  // 198.18.0.0/15 (Benchmark testing)
  if (p0 === 198 && (p1 === 18 || p1 === 19)) return true
  // 192.0.0.0/24 (IETF Protocol Assignments)
  if (p0 === 192 && p1 === 0 && p2 === 0) return true
  // 192.0.2.0/24 (Documentation/TEST-NET-1)
  if (p0 === 192 && p1 === 0 && p2 === 2) return true
  // 198.51.100.0/24 (Documentation/TEST-NET-2)
  if (p0 === 198 && p1 === 51 && p2 === 100) return true
  // 203.0.113.0/24 (Documentation/TEST-NET-3)
  if (p0 === 203 && p1 === 0 && p2 === 113) return true
  // Multicast & Reserved
  if (p0 >= 224) return true

  return false
}

function isPrivateIPv6 (ip: string): boolean {
  const normalized = ip.toLowerCase().trim()
  if (normalized === '::1' || normalized === '::') return true

  // Link-local: fe80::/10 (starts with fe8, fe9, fea, feb)
  if (normalized.startsWith('fe8') || normalized.startsWith('fe9') || normalized.startsWith('fea') || normalized.startsWith('feb')) return true

  // Unique local: fc00::/7 (starts with fc or fd)
  if (normalized.startsWith('fc') || normalized.startsWith('fd')) return true

  // IPv4-mapped IPv6 addresses like ::ffff:127.0.0.1 or ::ffff:192.168.1.1
  if (normalized.startsWith('::ffff:')) {
    const ipv4Part = normalized.substring(7)
    return isPrivateIPv4(ipv4Part)
  }

  // IPv4-compatible IPv6 addresses like ::127.0.0.1
  if (normalized.startsWith('::')) {
    const ipv4Part = normalized.substring(2)
    if (ipv4Part.includes('.')) {
      return isPrivateIPv4(ipv4Part)
    }
  }

  // Discard / Documentation prefixes
  if (normalized.startsWith('100::')) return true
  if (normalized.startsWith('2001:db8')) return true

  return false
}

function isPrivateHost (host: string): boolean {
  const normalized = host.toLowerCase().trim()
  if (normalized === 'localhost') return true
  if (normalized.endsWith('.local')) return true
  const cleanHost = normalized.startsWith('[') && normalized.endsWith(']')
    ? normalized.slice(1, -1)
    : normalized
  if (isPrivateIPv4(cleanHost) || isPrivateIPv6(cleanHost)) return true
  return false
}

async function isSafeUrl (urlStr: string): Promise<boolean> {
  try {
    const parsed = new URL(urlStr)
    if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
      return false
    }

    const hostname = parsed.hostname
    if (isPrivateHost(hostname)) {
      return false
    }

    try {
      const addresses = await dns.promises.lookup(hostname, { all: true })
      for (const addr of addresses) {
        if (isPrivateIPv4(addr.address) || isPrivateIPv6(addr.address)) {
          return false
        }
      }
    } catch {
      // DNS lookup failed
      return false
    }

    return true
  } catch {
    return false
  }
}

export function profileImageUrlUpload () {
  return async (req: Request, res: Response, next: NextFunction) => {
    if (req.body.imageUrl !== undefined) {
      const url = req.body.imageUrl
      if (url.match(/(.)*solve\/challenges\/server-side(.)*/) !== null) req.app.locals.abused_ssrf_bug = true
      const loggedInUser = security.authenticatedUsers.get(req.cookies.token)
      if (loggedInUser) {
        try {
          const safe = await isSafeUrl(url)
          if (!safe) {
            throw new Error('SSRF protection: requested URL is not safe')
          }
          const response = await fetch(url, { redirect: 'error' })
          if (!response.ok || !response.body) {
            throw new Error('url returned a non-OK status code or an empty body')
          }
          const ext = ['jpg', 'jpeg', 'png', 'svg', 'gif'].includes(url.split('.').slice(-1)[0].toLowerCase()) ? url.split('.').slice(-1)[0].toLowerCase() : 'jpg'
          const fileStream = fs.createWriteStream(`frontend/dist/frontend/assets/public/images/uploads/${loggedInUser.data.id}.${ext}`, { flags: 'w' })
          await finished(Readable.fromWeb(response.body as any).pipe(fileStream))
          const user = await UserModel.findByPk(loggedInUser.data.id)
          await user?.update({ profileImage: `/assets/public/images/uploads/${loggedInUser.data.id}.${ext}` })
        } catch (error) {
          try {
            const user = await UserModel.findByPk(loggedInUser.data.id)
            await user?.update({ profileImage: url })
            logger.warn(`Error retrieving user profile image: ${utils.getErrorMessage(error)}; using image link directly`)
          } catch (error) {
            next(error)
            return
          }
        }
      } else {
        next(new Error('Blocked illegal activity by ' + req.socket.remoteAddress))
        return
      }
    }
    res.location(process.env.BASE_PATH + '/profile')
    res.redirect(process.env.BASE_PATH + '/profile')
  }
}
