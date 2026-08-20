#!/usr/bin/env node

import http from 'node:http'

const listenHost = process.env.LISTEN_HOST ?? '127.0.0.1'
const listenPort = Number(process.env.LISTEN_PORT ?? '8080')
const origin = new URL(process.env.ORIGIN_URL ?? 'https://conet.network')

if (origin.protocol !== 'https:') {
  throw new Error('ORIGIN_URL must use https')
}

const server = http.createServer(async (request, response) => {
  if (request.method !== 'GET' && request.method !== 'HEAD') {
    response.writeHead(405, { allow: 'GET, HEAD' })
    response.end()
    return
  }

  const target = new URL(request.url ?? '/', origin)
  target.hostname = origin.hostname
  target.protocol = origin.protocol
  target.port = origin.port

  try {
    const upstream = await fetch(target, {
      method: request.method,
      redirect: 'manual',
      headers: {
        accept: request.headers.accept ?? '*/*',
        'user-agent': 'conet-l0d-web3-origin-proxy/1',
      },
    })

    const headers = {}
    for (const name of ['content-type', 'cache-control', 'etag', 'last-modified', 'location']) {
      const value = upstream.headers.get(name)
      if (value) headers[name] = value
    }
    response.writeHead(upstream.status, headers)
    if (request.method === 'HEAD') {
      response.end()
      return
    }
    response.end(Buffer.from(await upstream.arrayBuffer()))
  } catch (error) {
    console.error(`[origin-proxy] ${error instanceof Error ? error.message : String(error)}`)
    response.writeHead(502, { 'content-type': 'text/plain; charset=utf-8' })
    response.end('upstream unavailable')
  }
})

server.listen(listenPort, listenHost, () => {
  console.log(`[origin-proxy] listening on http://${listenHost}:${listenPort}`)
})
