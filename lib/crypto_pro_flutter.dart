import 'dart:io';


import 'package:crypto_pro_flutter/models/plugin_models.dart';

import 'crypto_pro_flutter_platform_interface.dart';

class CryptoProFlutter {
  /// Инициализация провайдера
  Future<bool> initCSP() {
    return CryptoProFlutterPlatform.instance.initCSP();
  }

  /// Проверка статуса лицензии
  Future<String> getLicenceStatus() {
    return CryptoProFlutterPlatform.instance.getLicenceStatus();
  }

  Future<License> getLicenceData() {
    return CryptoProFlutterPlatform.instance.getLicenceData();
  }

  Future<List<Certificate>> getASCPCertificates() async {
    return await CryptoProFlutterPlatform.instance.getASCPCertificates();
  }

  /// Добавить новый сертификат в формате Pfx
  Future<Certificate> addPfxCertificate(File file, String password) async {
    return await CryptoProFlutterPlatform.instance.addCertificate(file, password);
  }

  /// Удалить установленный сертификат
  Future<void> deleteCertificate(Certificate certificate) async {
    await CryptoProFlutterPlatform.instance.deleteCertificate(certificate);
  }

  /// Получит список установленных сертификатов
  Future<List<Certificate>> getInstalledCertificates() async {
    final list = await CryptoProFlutterPlatform.instance.getInstalledCertificates();
    return list;
  }

  /// Подписать файл
  Future<String> signFile({
    required File file,
    required Certificate certificate,
    required String password,
    bool isDetached = true,
    bool disableOnlineValidation = false,
  }) async {
    return await CryptoProFlutterPlatform.instance.signFile(
      file: file,
      certificate: certificate,
      password: password,
      isDetached: true,
      disableOnlineValidation: disableOnlineValidation,
    );
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
}
