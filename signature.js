//Require package crypto.js
const HmacSHA256 = require("crypto-js/hmac-sha256");
const SHA256 = require("crypto-js/sha256");
const Base64 = require("crypto-js/enc-base64");

/**
 * Sign request using HMAC-SHA256 schema.
 * @param {String} method GET, PUT, POST, DELETE
 * @param {String} path  path+query
 * @param {String} secret secret key
 * @param {String} timestamp http timestamp from Date or x-yoov-date header
 * @param {String} body Request content
 * @returns HMAC-SHA256 hashed Signature (base64 encoded)
 */
function sign(method, path, secret, timestamp, body) {
  //console.log(method, path, secret, timestamp, body);
  const verb = method.toUpperCase();
  const contentHash = SHA256(body).toString(Base64);
  //console.log("contentHash", contentHash);
  let strToBeSigned = `${verb}\n${path}\n${timestamp}\n${contentHash}`;
  return HmacSHA256(strToBeSigned, secret).toString(Base64);
}
