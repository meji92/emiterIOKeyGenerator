const crypto = require("crypto")

function newLicense (callback){
    var raw = new Uint8Array(24)
    raw = crypto.randomFillSync(raw).buffer
    var dv = new DataView(raw, 0);
    return {
        EncryptionKey: Buffer.from(raw.slice(0, 16)).toString('base64'),
        Contract: dv.getUint32(16),
        Signature: dv.getUint32(20),
        Expires: 0,
        Type: 2
    }
}

function getlicenseBase64(){
    let license = newLicense()
    let buf = Buffer.alloc(32)
    let b2 = Buffer.from(license.EncryptionKey, 'base64')
    b2.copy(buf)
    buf.writeUInt32BE(license.Contract, 16)
    buf.writeUInt32BE(license.Signature, 20)
    buf.writeUInt32BE(license.Expires, 24)
    buf.writeUInt32BE(license.Type, 28)
    let objJsonStr = JSON.stringify(license)
    let objJsonB64 = Buffer.from(buf).toString("base64")
    return objJsonB64.replace(/=/g, "").replace(/\+/g, "-").replace(/\//g, "_")
}