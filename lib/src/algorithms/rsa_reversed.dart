part of encrypt;

/// Wraps the RSA Engine Algorithm.
class RSAReversed extends AbstractRSA implements Algorithm {
  RSAReversed({RSAPublicKey? publicKey, RSAPrivateKey? privateKey, RSAEncoding encoding = RSAEncoding.PKCS1})
      : super(publicKey: publicKey, privateKey: privateKey, encoding: encoding);

  @override
  Encrypted encrypt(Uint8List bytes, {IV? iv}) {
    if (privateKey == null) {
      throw StateError('Can\'t encrypt without a private key, null given.');
    }

    _cipher
      ..reset()
      ..init(true, _privateKeyParams);

    return Encrypted(_cipher.process(bytes));
  }

  @override
  Uint8List decrypt(Encrypted encrypted, {IV? iv}) {
    if (publicKey == null) {
      throw StateError('Can\'t decrypt without a public key, null given.');
    }

    _cipher
      ..reset()
      ..init(false, _publicKeyParams);

    return _cipher.process(encrypted.bytes);
  }
}

class RSAReversedSigner extends AbstractRSA implements SignerAlgorithm {
  final RSASignDigest digest;
  final Uint8List _digestId;
  final Digest _digestCipher;

  RSAReversedSigner(this.digest, {RSAPublicKey? publicKey, RSAPrivateKey? privateKey})
      : _digestId = _digestIdFactoryMap[digest].id,
        _digestCipher = _digestIdFactoryMap[digest].factory(),
        super(publicKey: publicKey, privateKey: privateKey);

  @override
  Encrypted sign(Uint8List bytes) {
    final hash = Uint8List(_digestCipher.digestSize);

    _digestCipher
      ..reset()
      ..update(bytes, 0, bytes.length)
      ..doFinal(hash, 0);

    _cipher
      ..reset()
      ..init(true, _publicKeyParams);

    return Encrypted(_cipher.process(_encode(hash)));
  }

  @override
  bool verify(Uint8List bytes, Encrypted signature) {
    final hash = Uint8List(_digestCipher.digestSize);

    _digestCipher
      ..reset()
      ..update(bytes, 0, bytes.length)
      ..doFinal(hash, 0);

    _cipher
      ..reset()
      ..init(false, _privateKeyParams);

    var _signature = Uint8List(_cipher.outputBlockSize);

    try {
      final length = _cipher.processBlock(signature.bytes, 0, signature.bytes.length, _signature, 0);
      _signature = _signature.sublist(0, length);
    } on ArgumentError {
      return false;
    }

    final expected = _encode(hash);

    if (_signature.length == expected.length) {
      for (var i = 0; i < _signature.length; i++) {
        if (_signature[i] != expected[i]) {
          return false;
        }
      }

      return true;
    } else if (_signature.length == expected.length - 2) {
      var sigOffset = _signature.length - hash.length - 2;
      var expectedOffset = expected.length - hash.length - 2;

      expected[1] -= 2;
      expected[3] -= 2;

      var nonEqual = 0;

      for (var i = 0; i < hash.length; i++) {
        nonEqual |= (_signature[sigOffset + i] ^ expected[expectedOffset + i]);
      }

      for (int i = 0; i < sigOffset; i++) {
        nonEqual |= (_signature[i] ^ expected[i]);
      }

      return nonEqual == 0;
    } else {
      return false;
    }
  }

  Uint8List _encode(Uint8List hash) {
    final digestBytes = Uint8List(2 + 2 + _digestId.length + 2 + 2 + hash.length);
    var i = 0;

    digestBytes[i++] = 48;
    digestBytes[i++] = digestBytes.length - 2;
    digestBytes[i++] = 48;
    digestBytes[i++] = _digestId.length + 2;

    digestBytes.setAll(i, _digestId);
    i += _digestId.length;

    digestBytes[i++] = 5;
    digestBytes[i++] = 0;
    digestBytes[i++] = 4;
    digestBytes[i++] = hash.length;

    digestBytes.setAll(i, hash);

    return digestBytes;
  }
}
