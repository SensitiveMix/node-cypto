const fs = require('fs')
const md5 = require('js-md5')
const ALLOWS_LAG_SECONDS = 30
const moment = require('moment')
const httpSignature = require('http-signature')

class HttpServerHandler {
    constructor(opt) {
        this.req = opt.req
        this.res = opt.res
        this.next = opt.next
        this.publicKeys = opt.publicKeys
    }

    sendRes() {
        if (!this.req.headers.date) {
            return res.status(400)
                .json({msg: 'date header is required'})
        }
        this._processRes([this._checkSignature(req), HttpServerHandler._checkHeaderDate(this.req.headers.date), this._checkContentSignature(req)])
    }

    _checkSignature() {
        let _parsed = httpSignature.parseRequest(this.req)
        let pub = this._loadPublicKey()
        return httpSignature.verifySignature(_parsed, pub)
    }

    _loadPublicKey() {
        this._publicKeys = {}
        for (let name in this.publicKeys) {
            this._publicKeys[name] = fs.readFileSync(this.publicKeys[name], 'ascii')
            if (!this._publicKeys[name]) {
                throw new Error('Load public.pem key failed.')
            }
        }
    }

    _checkContentSignature() {
        const contentMd5 = this.req.headers['content-md5']
        let content = '' + this.req.method.toLowerCase() + this.req._parsedUrl.path
        if (this.req.body) {
            content = content + JSON.stringify(this.req.body)
        }
        return md5(content) === contentMd5
    }

    static _checkHeaderDate(datetime) {
        let status = true
        if (!this.req.headers.date) {
            return res.status(400)
                .json({msg: 'date header is required'})
        }
        return moment(Date.parse(datetime)).add(ALLOWS_LAG_SECONDS, 'seconds').isAfter(moment(new Date()))
    }

    _processRes(..._args) {
        new Promise((resolve, reject) => {
            for (let point in _args) {
                if (!point) {
                    throw {status: 401, msg: 'authorization failed'}
                }
            }
            resolve(null,true)
        }).then((done)=>{this.res.send({})})
            .catch((err) => {
            this.res.status(err.status).json({msg: err.msg})
        })
    }
}