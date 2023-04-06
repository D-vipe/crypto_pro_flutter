part of 'plugin_models.dart';

class License {
  final String serialNumber;
  final String maskedNumber;
  final String expiredThrough;
  final String status;
  final int? existingLicenseStatus;
  final int? type;

  License({required this.serialNumber, required this.expiredThrough, required this.status, required this.maskedNumber, this.existingLicenseStatus, this.type});

  factory License.fromJson(Map<String, dynamic> json) => License(
      serialNumber: json['serialNumber'] ?? '',
      expiredThrough: json['expiredThrough'] ?? '',
      status: json['status'],
      maskedNumber: json['maskedNumber'] ?? '',
      existingLicenseStatus: json['existingLicenseStatus'] ?? '',
      type: json['licenseType']);
}
