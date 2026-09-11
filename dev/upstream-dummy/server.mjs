import { createServer } from 'node:http'

const port = Number(process.env.PORT || '3000')
const staticUpstreamToken = 'Bearer local-upstream-token'
const authCredentials = {
  client_id: 'local-client',
  client_secret: 'local-secret',
}
const dynamicTokenLifetimeSeconds = 60
const maxAuthBodyBytes = 64 * 1024

let dynamicTokenSequence = 0
const issuedDynamicTokens = new Map()

function writeJson(response, statusCode, payload, headers = {}) {
  response.writeHead(statusCode, {
    'content-type': 'application/json',
    ...headers,
  })
  response.end(JSON.stringify(payload))
}

function isStaticAuthorized(request) {
  return request.headers.authorization === staticUpstreamToken
}

function isDynamicAuthorized(request) {
  const authorization = request.headers.authorization || ''
  const token = authorization.startsWith('Bearer ')
    ? authorization.slice('Bearer '.length)
    : ''
  const expiresAt = issuedDynamicTokens.get(token)

  if (expiresAt === undefined || Date.now() >= expiresAt) {
    issuedDynamicTokens.delete(token)
    return false
  }

  return true
}

function pruneExpiredDynamicTokens(now) {
  for (const [token, expiresAt] of issuedDynamicTokens) {
    if (now >= expiresAt) {
      issuedDynamicTokens.delete(token)
    }
  }
}

async function readJson(request) {
  const chunks = []
  let size = 0

  for await (const chunk of request) {
    size += chunk.length
    if (size > maxAuthBodyBytes) {
      const error = new Error('request_too_large')
      error.code = 'request_too_large'
      throw error
    }
    chunks.push(chunk)
  }

  try {
    return JSON.parse(Buffer.concat(chunks).toString('utf8'))
  } catch {
    const error = new Error('invalid_json')
    error.code = 'invalid_json'
    throw error
  }
}

async function handleAuthToken(request, response) {
  if (request.method !== 'POST') {
    writeJson(response, 405, { error: 'method_not_allowed' }, { allow: 'POST' })
    return
  }

  const contentType = request.headers['content-type'] || ''
  if (contentType.split(';', 1)[0].trim().toLowerCase() !== 'application/json') {
    writeJson(response, 415, { error: 'unsupported_media_type' })
    return
  }

  let credentials
  try {
    credentials = await readJson(request)
  } catch (error) {
    const statusCode = error.code === 'request_too_large' ? 413 : 400
    writeJson(response, statusCode, { error: error.code })
    return
  }

  if (
    credentials === null ||
    typeof credentials !== 'object' ||
    Array.isArray(credentials)
  ) {
    writeJson(response, 400, { error: 'invalid_credentials_payload' })
    return
  }

  if (
    credentials.client_id !== authCredentials.client_id ||
    credentials.client_secret !== authCredentials.client_secret
  ) {
    writeJson(response, 401, { error: 'invalid_credentials' })
    return
  }

  dynamicTokenSequence += 1
  const token = `local-dynamic-token-${dynamicTokenSequence}`
  const now = Date.now()
  pruneExpiredDynamicTokens(now)
  issuedDynamicTokens.set(
    token,
    now + dynamicTokenLifetimeSeconds * 1000,
  )
  writeJson(response, 200, {
    token,
    expires_in: dynamicTokenLifetimeSeconds,
  })
}

function streamTasks(request, response) {
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
}

function handleProjectRoutes(request, response, pathname, prefix) {
  const { method = 'GET' } = request
  const tasksPath = `${prefix}/projects/1/tasks`

  if (pathname === tasksPath && method === 'GET') {
    writeJson(response, 200, {
      tasks: [{ id: 1, name: 'Local dummy task', status: 'open' }],
    })
    return true
  }

  if (pathname === tasksPath && method === 'POST') {
    writeJson(response, 201, {
      id: 2,
      name: 'Local dummy task',
      status: 'created',
    })
    return true
  }

  if (pathname === `${tasksPath}/stream` && method === 'GET') {
    streamTasks(request, response)
    return true
  }

  return false
}

const server = createServer(async (request, response) => {
  const url = new URL(request.url || '/', 'http://127.0.0.1')

  if (url.pathname === '/healthz') {
    writeJson(response, 200, { status: 'ok' })
    return
  }

  if (url.pathname === '/auth/token') {
    await handleAuthToken(request, response)
    return
  }

  if (url.pathname.startsWith('/api/v1/')) {
    if (!isStaticAuthorized(request)) {
      writeJson(response, 401, { error: 'unauthorized' })
      return
    }
    if (!handleProjectRoutes(request, response, url.pathname, '/api/v1')) {
      writeJson(response, 404, { error: 'not_found' })
    }
    return
  }

  if (url.pathname.startsWith('/api/v2/')) {
    if (!isDynamicAuthorized(request)) {
      writeJson(response, 401, { error: 'unauthorized' })
      return
    }
    if (!handleProjectRoutes(request, response, url.pathname, '/api/v2')) {
      writeJson(response, 404, { error: 'not_found' })
    }
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
