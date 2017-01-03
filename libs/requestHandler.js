const fs = require('fs')
const md5 = require('js-md5')
const httpSignature = require('http-signature')

class HttpSignatureRequest {
  constructor ({ privateKeys, host, port, useHttps = true, headers = {} }) {
    if (!privateKeys || Object.keys(privateKeys).length === 0) {
      throw new Error('privateKeys is required.')
    }
    if (!host) { throw new Error('`host` is required.') }

    this._loadPrivateKey(privateKeys)
    this.host = host
    this._useHttps = useHttps
    this.headers = headers
    if (port) { this._port = port }
  }

  get port () {
    if (this._port) { return this._port }
    if (this._useHttps) { return 443 }
    return 80
  }

  sendReq ({ keyId, method, postData, path, headers }) {
    if (keyId) {
      this._keyId = keyId
    } else {
      this._keyId = Object.keys(this.privateKeys)[0]
    }

    if (!method) { method = 'GET' }
    if (path) { this.path = path }
    if (headers) { this.headers = headers }

    if (!this.path) { throw new Error('`path` is required.') }

    let options = {
      method: method,
      host: this.host,
      path: this.path,
      port: this.port,
      headers: this.headers
    }

    const http = this._getHttp()
    this.headers['content-md5'] = this._getContentMd5(method, postData)
    this.headers['date'] = new Date(+new Date - 8 * 3600 * 1000)
    return new Promise((resolve, reject) => {
      this._req = http.request(options, (res) => { resolve(res) })
      this._signReq()
      if (postData && Object.keys(postData).length !== 0) {
        this._req.write(require('querystring').stringify(postData))
      }
      this._req.end()
    })
      .then(this._processRes)
  }

  _loadPrivateKey (privateKeys) {
    this._privateKeys = {}
    for (let name in privateKeys) {
      this._privateKeys[name] = fs.readFileSync(privateKeys[name], 'ascii')
      if (!this._privateKeys[name]) {
        throw new Error('Load private key failed.')
      }
    }
  }

  _getHttp () {
    return this._useHttps ? require('https') : require('http')
  }

  _getContentMd5 (method, postData) {
    let content = `${method.toLowerCase()}${this.path}`
    if (postData) {
      content = content + JSON.stringify(postData)
    }
    return md5(content)
  }

  _signReq () {
    httpSignature.sign(this._req, { key: this._privateKeys[this._keyId], keyId: this._keyId })
  }

  _processRes (res) {
    return new Promise((resolve, reject) => {
      let body = ''
      res.on('data', function (d) { body += d })
      res.on('end', function () {
        resolve({
          statusCode: res.statusCode,
          statusMessage: res.statusMessage,
          body: body
        })
      })
    })
  }
}


module.exports = HttpSignatureRequest