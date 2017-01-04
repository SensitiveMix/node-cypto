const Request = require('../libs/client')
const should = require('should')
const expect = require('expect')
const privateKeys = require('./certificate/private.js')
const host = '127.0.0.1'
const port = '3001'
const nock = require('nock')(`http://${host}:${port}`)


describe('request signature unit test', function () {
    before(() => {
        nock
            .get('/verify')
            .reply(200, {"msg": "ok"})
    })

    it('should resolve request if valid header', function (done) {
        let request = new Request(privateKeys, host, port)
        request.sendReq('phoenix-test', 'GET', {key: '123'}, "/verify")
            .then((res) => {
                expect(res.statusCode).toBe(200)
                expect(res.body.msg).toBe('ok')
            })
        done()
    })
})