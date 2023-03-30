class License {
  final String serialNumber;
  final String maskedNumber;
  final String expiredThrough;
  final String installDate;

  License({required this.serialNumber, required this.expiredThrough, required this.maskedNumber, required this.installDate});

  factory License.fromJson(Map<String, dynamic> json) => License(
        serialNumber: json['serialNumber'] ?? '',
        expiredThrough: json['expiredThrough'] ?? '',
        maskedNumber: json['maskedNumber'] ?? '',
        installDate: json['installDate'] ?? '',
      );
}
