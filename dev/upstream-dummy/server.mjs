import { createServer } from 'node:http'

const port = Number(process.env.PORT || '3000')
const upstreamToken = 'Bearer local-upstream-token'

function writeJson(response, statusCode, payload, headers = {}) {
  response.writeHead(statusCode, {
    'content-type': 'application/json',
    ...headers,
  })
  response.end(JSON.stringify(payload))
}

function isAuthorized(request) {
  return request.headers.authorization === upstreamToken
}

const server = createServer((request, response) => {
  const url = new URL(request.url || '/', 'http://127.0.0.1')
  const { method = 'GET' } = request

  if (url.pathname === '/healthz') {
    writeJson(response, 200, { status: 'ok' })
    return
  }

  if (!isAuthorized(request)) {
    writeJson(response, 401, { error: 'unauthorized' })
    return
  }

  if (url.pathname === '/api/v1/projects/1/tasks' && method === 'GET') {
    writeJson(response, 200, {
      tasks: [{ id: 1, name: 'Local dummy task', status: 'open' }],
    })
    return
  }

  if (url.pathname === '/api/v1/projects/1/tasks' && method === 'POST') {
    writeJson(response, 201, {
      id: 2,
      name: 'Local dummy task',
      status: 'created',
    })
    return
  }

  if (url.pathname === '/api/v1/projects/1/tasks/stream' && method === 'GET') {
    response.writeHead(200, {
      'content-type': 'application/x-ndjson',
      'cache-control': 'no-cache',
      connection: 'keep-alive',
      'x-accel-buffering': 'no',
    })

    const chunks = [
      JSON.stringify({ type: 'task', id: 1, status: 'open' }) + '\n',
      JSON.stringify({ type: 'task', id: 2, status: 'running' }) + '\n',
      JSON.stringify({ type: 'task', id: 3, status: 'done' }) + '\n',
    ]

    let index = 0
    const timer = setInterval(() => {
      if (index >= chunks.length) {
        clearInterval(timer)
        response.end()
        return
      }

      response.write(chunks[index])
      index += 1
    }, 200)

    request.on('close', () => {
      clearInterval(timer)
    })

    return
  }

  if (url.pathname.startsWith('/api/')) {
    writeJson(response, 404, { error: 'not_found' })
    return
  }

  writeJson(response, 404, { error: 'not_found' })
})

server.listen(port, '0.0.0.0', () => {
  process.stdout.write(`dummy-upstream listening on ${port}\n`)
})
