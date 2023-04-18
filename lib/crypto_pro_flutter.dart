import 'dart:io';

import 'package:crypto_pro_flutter/models/plugin_models.dart';

import 'crypto_pro_flutter_platform_interface.dart';

class CryptoProFlutter {
  /// Инициализация провайдера
  Future<bool> initCSP() {
    return CryptoProFlutterPlatform.instance.initCSP();
  }

  Future<void> installCACerts() {
    return CryptoProFlutterPlatform.instance.installCACerts();
  }

  /// Проверка статуса лицензии
  Future<String> getLicenceStatus() {
    return CryptoProFlutterPlatform.instance.getLicenceStatus();
  }

  Future<License> getLicenceData() {
    return CryptoProFlutterPlatform.instance.getLicenceData();
  }

  Future<License?> setNewLicense(String number) {
    return CryptoProFlutterPlatform.instance.setNewLicense(number);
  }

  Future<bool> copyContainerFromDir(
      {required List<String> files, required String dirName}) async {
    return await CryptoProFlutterPlatform.instance
        .copyContainerFromDir(files: files, dirName: dirName);
  }

  /// Добавить новый сертификат в формате Pfx
  Future<Certificate> addPfxCertificate(File file, String password) async {
    try {
      return await CryptoProFlutterPlatform.instance
          .addCertificate(file, password);
    } catch (e) {
      rethrow;
    }
  }

  /// Удалить установленный сертификат
  Future<void> deleteCertificate(Certificate certificate) async {
    await CryptoProFlutterPlatform.instance.deleteCertificate(certificate);
  }

  /// Получит список установленных сертификатов
  Future<List<Certificate>> getInstalledCertificates() async {
    final list =
        await CryptoProFlutterPlatform.instance.getInstalledCertificates();
    return list;
  }

  /// Подписать файл
  Future<String> signFile({
    required File file,
    required String certificateAlias,
    required String password,
    bool isDetached = true,
    bool disableOnlineValidation = false,
  }) async {
    try {
      return await CryptoProFlutterPlatform.instance.signFile(
        file: file,
        certificateAlias: certificateAlias,
        password: password,
        isDetached: true,
        disableOnlineValidation: disableOnlineValidation,
      );
    } catch (_) {
      rethrow;
    }
  }

  /// Подписать сообщение
  Future<String> signMessage({
    required String message,
    required Certificate certificate,
    required String password,
    bool isDetached = true,
    bool signHash = false,
    bool disableOnlineValidation = false,
  }) async {
    return await CryptoProFlutterPlatform.instance.signMessage(
      message: message,
      certificate: certificate,
      password: password,
      isDetached: isDetached,
      signHash: signHash,
      disableOnlineValidation: disableOnlineValidation,
    );
  }

  Future<Map<String, dynamic>> verify({
    required String signature,
    String? signedData,
  }) async {
    Map<String, dynamic> result = {
      'result': false,
      'certificates': [],
      'message': ''
    };

    result = await CryptoProFlutterPlatform.instance.verifySignature(
      signature: signature,
      signedData: signedData,
    );

    return result;
  }
}
