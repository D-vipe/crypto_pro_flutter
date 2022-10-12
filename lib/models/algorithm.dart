class Algorithm {
  /// Список поддерживаемых алгоритмов
  static List<Algorithm> algorithms = [
    Algorithm(
      name: "ГОСТ Р 34.10-2001",
      hashOID: "1.2.643.2.2.9",
      publicKeyOID: "1.2.643.2.2.19",
      signatureOID: "1.2.643.2.2.3",
    ),
    Algorithm(
      name: "ГОСТ Р 34.10-2012",
      hashOID: "1.2.643.7.1.1.2.2",
      publicKeyOID: "1.2.643.7.1.1.1.1",
      signatureOID: "1.2.643.7.1.1.3.2",
    ),
    Algorithm(
      name: "ГОСТ Р 34.10-2012 Strong",
      hashOID: "1.2.643.7.1.1.2.3",
      publicKeyOID: "1.2.643.7.1.1.1.2",
      signatureOID: "1.2.643.7.1.1.3.3",
    ),
    Algorithm(
      name: "Неизвестен",
      hashOID: "Неизвестен",
      publicKeyOID: "Неизвестен",
      signatureOID: "Неизвестен",
    ),
  ];

  /// Название алгоритма
  final String? name;
  final String? hashOID;
  final String? publicKeyOID;
  final String? signatureOID;

  Algorithm({
    this.name,
    this.hashOID,
    this.publicKeyOID,
    this.signatureOID,
  });

  static Algorithm findAlgorithmByPublicKeyOID(String? publicKeyOID) {
    if (publicKeyOID == null) return algorithms.last;

    final String formattedPublicKeyOID = formatOID(publicKeyOID);
    return algorithms.firstWhere((algorithm) => algorithm.publicKeyOID == formattedPublicKeyOID,
        orElse: () => algorithms.last);
  }

  static String formatOID(String rawOID) =>
      rawOID.replaceAll("[", "").replaceAll("]", "").replaceAll(" ", "").replaceAll(",", ".");

  Map<String, String?> toJson() => {
        'name': name,
        'hashOID': hashOID,
        'publicKeyOID': publicKeyOID,
        'signatureOID': signatureOID,
      };

  Algorithm.fromJson(Map<String, String?> json)
      : name = json['name'] != null ? json['name'] as String : null,
        hashOID = json['hashOID'] != null ? json['hashOID'] as String : null,
        publicKeyOID = json['publicKeyOID'] != null ? json['publicKeyOID'] as String : null,
        signatureOID = json['signatureOID'] != null ? json['signatureOID'] as String : null;
}
