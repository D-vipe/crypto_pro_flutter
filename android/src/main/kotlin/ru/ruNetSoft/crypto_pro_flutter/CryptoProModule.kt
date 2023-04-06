package ru.ruNetSoft.crypto_pro_flutter

import android.content.Context
import android.content.pm.ApplicationInfo
import android.util.Log
import androidx.documentfile.provider.DocumentFile
import org.json.JSONArray
import org.json.JSONException
import org.json.JSONObject
import ru.CryptoPro.AdES.AdESConfig
import ru.CryptoPro.AdES.Options
import ru.CryptoPro.CAdES.CAdESSignature
import ru.CryptoPro.CAdES.CAdESType
import ru.CryptoPro.JCP.KeyStore.JCPPrivateKeyEntry
import ru.CryptoPro.JCP.params.JCPProtectionParameter
import ru.CryptoPro.JCP.tools.Encoder
import ru.CryptoPro.JCSP.CSPConfig
import ru.CryptoPro.JCSP.CSPProviderInterface
import ru.CryptoPro.JCSP.JCSP
import ru.CryptoPro.JCSP.support.BKSTrustStore
import ru.CryptoPro.reprov.RevCheck
import ru.CryptoPro.ssl.util.cpSSLConfig
import ru.cprocsp.ACSP.tools.common.AppUtils
import ru.cprocsp.ACSP.tools.common.CSPTool
import ru.cprocsp.ACSP.tools.common.RawResource
import ru.cprocsp.ACSP.tools.license.CSPLicenseConstants
import ru.cprocsp.ACSP.tools.license.LicenseInterface
import ru.ruNetSoft.crypto_pro_flutter.exceptions.NoPrivateKeyFound
import java.io.*
import java.security.KeyStore
import java.security.KeyStoreException
import java.security.PrivateKey
import java.security.Security
import java.security.cert.X509Certificate
import java.util.*

/** Модуль для работы с Crypto Pro */
class CryptoProModule {
    var cAdESCAInstalled: Boolean = false;
    companion object Factory {
        private var instance: CryptoProModule? = null

        fun getInstance(): CryptoProModule {
            if (instance == null) instance = CryptoProModule()
            return instance!!
        }
    }

    /** Инициализация провайдера */
    fun initCSP(context: Context): Boolean {
        val initCode = CSPConfig.init(context)
        val initOk = initCode == CSPConfig.CSP_INIT_OK
        if (initOk) {
            if (Security.getProvider(JCSP.PROVIDER_NAME) == null) {
                Security.addProvider(JCSP())
            }
            if (Security.getProvider(RevCheck.PROVIDER_NAME) == null) {
                Security.addProvider(RevCheck())
            }
            //
            // Отключаем проверку цепочки штампа времени (CAdES-T),
            // чтобы не требовать него CRL.
            //
            System.setProperty("ru.CryptoPro.CAdES.validate_tsp", "false")

            // Таймауты для CRL на всякий случай.
            System.setProperty("com.sun.security.crl.timeout", "10")
            System.setProperty("ru.CryptoPro.crl.read_timeout", "10")


            // Задание провайдера по умолчанию для CAdES.
            AdESConfig.setDefaultProvider(JCSP.PROVIDER_NAME)
            // https://cryptopro.ru/forum2/default.aspx?g=posts&t=20779
            cpSSLConfig.setDefaultSSLProvider(JCSP.PROVIDER_NAME)

            // Включаем возможность онлайновой проверки статуса
            // сертификата.
            //
            // В случае создания подписей формата BES или T можно отключить
            // проверку цепочки сертификатов подписанта (и службы) с помощью
            // параметра:
            // cAdESSignature.setOptions((new Options()).disableCertificateValidation()); // CAdES
            // или
            // xAdESSignature.setOptions((new Options()).disableCertificateValidation()); // XAdES
            // перед добавлением подписанта.
            // По умолчанию проверка цепочки сертификатов подписанта всегда
            // включена.
            System.setProperty("ru.CryptoPro.reprov.enableCRLDP", "true")
            System.setProperty("com.sun.security.enableCRLDP", "true")
            System.setProperty("com.ibm.security.enableCRLDP", "true")
            System.setProperty("ru.CryptoPro.reprov.enableAIAcaIssuers", "true")
            System.setProperty("com.sun.security.enableAIAcaIssuers", "true")
            System.setProperty("ngate_set_jcsp_if_gost", "true");
        }

        return initOk
    }

    /** Получить данные лицензии */
    fun getLicenceStatus(): String {
        val providerInfo: CSPProviderInterface = CSPConfig.INSTANCE.cspProviderInfo
        val license: LicenseInterface = providerInfo.license

        val licenseStatus: Int = license.checkAndSave()
        return returnLicenceStatus(license, licenseStatus)
    }

    fun getLicenceData(): JSONObject {
        return try {
            val providerInfo: CSPProviderInterface = CSPConfig.INSTANCE.cspProviderInfo
            val license: LicenseInterface = providerInfo.license
            val licenseStatus: Int = license.checkAndSave()

            val response = JSONObject()

            response.put("serialNumber", license.serialNumber)
            response.put("maskedNumber", license.maskedSerialNumber)
            response.put("expiredThrough", license.expiredThroughDays.toString())
            response.put("existingLicenseStatus", license.existingLicenseStatus)
            response.put("licenseType", license.licenseType)
            response.put("status", returnLicenceStatus(license, licenseStatus))
            response
        } catch (e: Exception) {
            getErrorResponse("Произошла непредвиденная ошибка при получении данных лицензии", e)
        }

    }

    fun setNewLicense(licenseNumber: String): JSONObject {
        return  try {
            val response = JSONObject()
            val providerInfo: CSPProviderInterface = CSPConfig.INSTANCE.cspProviderInfo

//            CSPConfig.INSTANCE.cspProviderInfo.config.setReaderName()

            var license: LicenseInterface = providerInfo.license

            val licenseStatus: Int = license.checkAndSave(licenseNumber, false)
            val saved: Boolean = licenseStatus == CSPLicenseConstants.LICENSE_STATUS_OK;

            if (saved) {
                license = providerInfo.license
            }

            response.put("serialNumber", license.serialNumber)
            response.put("maskedNumber", license.maskedSerialNumber)
            response.put("expiredThrough", if (license.licenseType == CSPLicenseConstants.LICENSE_TYPE_PERMANENT) "-1" else license.expiredThroughDays.toString())
            response.put("existingLicenseStatus", license.existingLicenseStatus)
            response.put("licenseType", license.licenseType)
            response.put("status", returnLicenceStatus(license, licenseStatus))
            response.put("success", saved)

            response
        } catch (e: Exception) {
            getErrorResponse("Произошла непредвиденная ошибка при установке новой лицензии", e)
        }
    }

    /** Копирование контейнера из папки пользователя */
    fun copyContainerFromDir(context: Context, cFiles: ArrayList<String>, dirName: String): Boolean {
        val cspTool = CSPTool(context)

        return try {
            val dstPath = StringBuilder()
            dstPath.append(cspTool.appInfrastructure.keysDirectory).append(File.separator)
                .append(userName2Dir(context))

            val dstContainer = File(dstPath.toString(), dirName)
            if (!dstContainer.exists() && !dstContainer.mkdirs()) {
                println("ACSP: Couldn't create store directory = ${dstContainer.absolutePath}")
                false
            } else {
                var containerFiles: ArrayList<DocumentFile> = ArrayList()
                for (path in cFiles) {
                    containerFiles.add(DocumentFile.fromFile(File(path)))
                }

                var copied = 0
                var count = containerFiles.size
                val containerSize = containerFiles.size
                for (i in 0 until containerSize) {
                    val srcCurrentContainerFile = containerFiles[i]
                    val fileName = srcCurrentContainerFile.name
                    if (fileName != null && fileName != "." && fileName != "..") {
                        if (fileName.lastIndexOf(".key") < 0) {
                            --count
                        } else {
                            println("ACSP: Copy file: $fileName")
                            try {
                                val `in`: InputStream? =
                                    context.contentResolver.openInputStream(srcCurrentContainerFile.uri)
                                if (!RawResource.writeStreamToFile(
                                        `in`,
                                        dstContainer.path,
                                        fileName
                                    )
                                ) {
                                    println("ACSP: file copied to: ${dstContainer.path}")
                                    println("ACSP: Couldn't copy file: $fileName")
                                } else {
                                    println("ACSP: File $fileName was copied successfully.")
                                    ++copied
                                }
                            } catch (exc: FileNotFoundException) {
                                println("ACSP Exception: exc.message")
                            }
                        }
                    }
                }
                count > 0 && copied == count
            }
        } catch (e: Exception) {
            println("ERROR OCCURRED IN copyContainerFromDir, ${e.message}")
            getErrorResponse("Произошла непредвиденная ошибка при копировании ключевого контейнера", e)
            false
        }
    }

    private fun userName2Dir(appCtx: Context): String? {
        val appInfo: ApplicationInfo = appCtx.applicationInfo
        return appInfo.uid.toString() + "." + appInfo.uid
    }

    /** Вывод значений статуса лиценизии */
    private fun returnLicenceStatus(license: LicenseInterface, licenseStatus: Int): String {
        var result: String

        val licenseType: Int = license.licenseType

        result = if (licenseStatus == CSPLicenseConstants.LICENSE_STATUS_OK) {
            "активна"
        } // if
        else {
            if (licenseType == CSPLicenseConstants.LICENSE_TYPE_EXPIRED) {
                "истекла"
            } // if
            else {
                "номер лицензии неверен"
            } // else
        } // else


        if (licenseStatus != CSPLicenseConstants.LICENSE_STATUS_INVALID) {
            result = when (licenseType) {
                CSPLicenseConstants.LICENSE_TYPE_EXPIRED -> {
                    "истекла"
                } // if
                CSPLicenseConstants.LICENSE_TYPE_PERMANENT -> {
                    "перманентная"
                } // else if
                else -> {
                    "активна"
                }
            } // else
        } // if

        return result
    }

    /** Получить файл хранилища доверенных сертификатов */
    private fun getBksTrustStore(): File {
        val trustStorePath = CSPConfig.getBksTrustStore() + File.separator +
                BKSTrustStore.STORAGE_FILE_TRUST

        val trustStoreFile = File(trustStorePath)
        if (!trustStoreFile.exists()) {
            throw Exception(
                "Trust store " + trustStorePath +
                        " doesn't exist"
            )
        } else {
            return trustStoreFile
        }
    }

    /** Проверить, есть ли сертификат в хранилище корневых сертификатов */
    private fun containsAliasInBks(alias: String): Boolean {
        val trustStoreFile = getBksTrustStore()
        val trustStoreStream = trustStoreFile.inputStream();
        val keyStore = KeyStore.getInstance(BKSTrustStore.STORAGE_TYPE)
        keyStore.load(
            trustStoreStream,
            BKSTrustStore.STORAGE_PASSWORD,
        )
        return keyStore.containsAlias(alias);
    }

    /** Добавить сертификат в хранилище доверенных сертификатов */
    private fun addToBksTrustStore(alias: String, certificate: X509Certificate) {
        val trustStoreFile = getBksTrustStore()
        val trustStoreStream = trustStoreFile.inputStream();
        val keyStore = KeyStore.getInstance(BKSTrustStore.STORAGE_TYPE)
        keyStore.load(
            trustStoreStream,
            BKSTrustStore.STORAGE_PASSWORD,
        )
        keyStore.setCertificateEntry(alias, certificate)
        val updatedTrustStore = FileOutputStream(trustStoreFile)
        keyStore.store(
            updatedTrustStore,
            BKSTrustStore.STORAGE_PASSWORD,
        )
        trustStoreStream.close()
    }

    /** Подписать файл */
    fun signFile(filePathToSign: String, alias: String, password: String, detached: Boolean, disableOnlineValidation: Boolean) : JSONObject {
        return try {
            val fileInputStream = FileInputStream(filePathToSign)
            val size = fileInputStream.available()
            val buffer = ByteArray(size)
            fileInputStream.read(buffer)
            fileInputStream.close()

            sign(buffer, alias, password, detached, false, disableOnlineValidation)
        } catch (e: NoPrivateKeyFound) {
            getErrorResponse("Не найден приватный ключ, связанный с сертификатом", e)
        } catch (e: Exception) {
            getErrorResponse("Произошла непредвиденная ошибка", e)
        }
    }

    /** Подписать сообщение */
    fun signMessage(contentToSign: String, alias: String, password: String, detached: Boolean, signHash: Boolean, disableOnlineValidation: Boolean) : JSONObject {
        return sign(contentToSign.toByteArray(), alias, password, detached, signHash, disableOnlineValidation)
    }

    /** Подписание массива байт */
    private fun sign(contentToSign: ByteArray, alias: String, password: String, detached: Boolean, signHash: Boolean, disableOnlineValidation: Boolean) : JSONObject {
        try {
            // Получаем из HDImage сертификат (которым будем подписывать) с приватным ключем
            val keyStore = KeyStore.getInstance(JCSP.HD_STORE_NAME, JCSP.PROVIDER_NAME)
            keyStore.load(null, null)
            val certificate = keyStore.getCertificate(alias) as X509Certificate
            val privateKey = keyStore.getKey(alias, password.toCharArray()) as PrivateKey

            // Формируем цепочку для подписи
            val chain: MutableList<X509Certificate> = ArrayList()

            println("CERTIFICATE CN: ${certificate.serialNumber}")

            chain.add(certificate)

            val cAdESSignature = CAdESSignature(detached, signHash)

            println("CADESSIGNATURE: ${cAdESSignature.toString()}")

            if (disableOnlineValidation) {
                cAdESSignature.setOptions((Options()).disableCertificateValidation());
            }

            var exception: Exception? = null;

            println("BEFORE GFG THREAD INIT")

            val gfgThread = Thread {
                try {
                    cAdESSignature.addSigner(
                        JCSP.PROVIDER_NAME, null, null, privateKey, chain,
                        CAdESType.CAdES_BES, null, false, null, null, null,
                        true
                    )
                } catch (e: Exception) {
                    println("EXCEPTION IN THREAD: ${e}")
                    exception = e
                }
            }

            println("BEFORE GFGTHREAD start")

            gfgThread.start()
            gfgThread.join();

            if (exception != null) {
                return getErrorResponse(exception.toString(), exception!!)
            }

            val signatureStream = ByteArrayOutputStream()

            println("SIGNATURE STREAM INITIATED ")

            cAdESSignature.open(signatureStream)
            cAdESSignature.update(contentToSign)

            cAdESSignature.close()
            signatureStream.close()

            val enc = Encoder()
            val base64 = enc.encode(signatureStream.toByteArray())


            val response = JSONObject()
            response.put("success", true)
            response.put("signBase64", base64)
            return response
        } catch (e: Exception) {
            return getErrorResponse("Произошла непредвиденная ошибка", e)
        }
    }


    /** Установка PFX-сертификата */
    fun addPfxCertificate(path: String, password: String, context: Context): JSONObject {
        try {
            // Загружаем pfx-файл в Pfx-KeyStore
            val keyStore = KeyStore.getInstance(JCSP.PFX_STORE_NAME, JCSP.PROVIDER_NAME)
            val fileInputStream: InputStream = FileInputStream(path)
            keyStore.load(null,null)
            keyStore.load(fileInputStream, password.toCharArray())
            // Получаем алиас сертификата с приватным ключем
            val mainCertAlias: String = findPrivateKeyAlias(keyStore)
            val certificate = keyStore.getCertificate(mainCertAlias) as X509Certificate
            val privateKey = keyStore.getKey(mainCertAlias, password.toCharArray()) as PrivateKey
            val chain = keyStore.getCertificateChain(mainCertAlias)
            // Загружаем цепочку в HDImage
            val hdKeyStore = KeyStore.getInstance(JCSP.HD_STORE_NAME, JCSP.PROVIDER_NAME)
            hdKeyStore.load(null, null)
            if (!hdKeyStore.containsAlias(mainCertAlias)) {
                val keyEntry = JCPPrivateKeyEntry(privateKey, chain, true)
                val parameter = JCPProtectionParameter(null)
                hdKeyStore.setEntry(mainCertAlias, keyEntry as KeyStore.Entry, parameter as KeyStore.PasswordProtection)
            }

            // Добавляем остальные сертификаты из pfx-файла в хранилище доверенных
            for (alias in keyStore.aliases().toList()) {
                if (alias != mainCertAlias && !containsAliasInBks(alias)) {
                    addToBksTrustStore(alias, keyStore.getCertificate(alias) as X509Certificate)
                }
            }



            val response = JSONObject()
            response.put("success", true)
            response.put("certificate", getJSONCertificate(mainCertAlias, certificate))
            return response
        } catch (e: NoPrivateKeyFound) {
            return getErrorResponse("Не найден приватный ключ, связанный с сертификатом", e)
        } catch (e: Exception) {
            return getErrorResponse("Произошла непредвиденная ошибка", e)
        }
    }


    /** Удаление PFX-сертификата */
    fun deletePfxCertificate(alias: String): JSONObject {
        try {
            val keyStore = KeyStore.getInstance(JCSP.HD_STORE_NAME, JCSP.PROVIDER_NAME)
            keyStore.load(null, null)
            keyStore.deleteEntry(alias)

            val response = JSONObject()
            response.put("success", true)
            return response
        } catch (e: NoPrivateKeyFound) {
            return getErrorResponse("Не найден приватный ключ, связанный с сертификатом", e)
        } catch (e: Exception) {
            return getErrorResponse("Произошла непредвиденная ошибка", e)
        }
    }

    /** Получение установленных сертификатов */
    fun getInstalledCertificates(): JSONObject {
        try {
            val keyStore = KeyStore.getInstance(JCSP.HD_STORE_NAME, JCSP.PROVIDER_NAME)
            keyStore.load(null, null)
            val aliases = keyStore.aliases().toList()
            val certificatesJSON = ArrayList<JSONObject>()

            for (alias in aliases) {
                val certificate = keyStore.getCertificate(alias) as X509Certificate
                val certificateJSON = getJSONCertificate(alias, certificate)
                certificatesJSON.add(certificateJSON)
            }

            val response = JSONObject()
            response.put("success", true)
            response.put("certificates", JSONArray(certificatesJSON))
            return response
        } catch (e: Exception) {
            return getErrorResponse("Произошла непредвиденная ошибка", e)
        }
    }

    /** Получаем JSON-модель по сертификату и алиасу */
    private fun getJSONCertificate(alias: String, certificate: X509Certificate): JSONObject {
        val certificateJSON = JSONObject()

        certificateJSON.put("alias", alias)
        certificateJSON.put("owner", certificate.subjectDN.name)
        certificateJSON.put("issuer", certificate.issuerDN.name)
        certificateJSON.put("serialNumber", certificate.serialNumber.toString())
        certificateJSON.put("algorithm", certificate.sigAlgName)
        certificateJSON.put("version", certificate.version.toString())
        certificateJSON.put("oid", certificate.sigAlgOID)
        certificateJSON.put("validFrom", certificate.notBefore.toString())
        certificateJSON.put("validTo", certificate.notAfter.toString())

        return certificateJSON;
    }

//    private fun checkCAdESCACertsAndInstall() {
//
//        // Установка корневых сертификатов для CAdES примеров.
//        if (!cAdESCAInstalled) {
//            val adapter = ContainerAdapter(getActivity(), null, false)
//            adapter.setProviderType(ProviderType.currentProviderType())
//            adapter.setResources(getResources())
//            try {
//                val installRootCert: CAdESData = InstallCAdESTestTrustCertExample(adapter)
//
//                // Если сертификаты не установлены, сообщаем об
//                // этом и устанавливаем их.
//                if (!installRootCert.isAlreadyInstalled()) {
//
//                    // Предупреждение о выполнении установки.
//                    AppUtils.errorMessage(getActivity(), message, false, false)
//                    Logger.clear()
//                    Logger.log("*** Forced installation of CA certificates (CAdES) ***")
//
//                    // Установка.
//                    installRootCert.getResult()
//                } // if
//                cAdESCAInstalled = true
//            } catch (e: Exception) {
//                Logger.setStatusFailed()
//                Log.e(Constants.APP_LOGGER_TAG, e.message, e)
//            }
//        }
//    }

    /** Поиск алиаса для сертификата с приватным ключем */
    @Throws(KeyStoreException::class, NoPrivateKeyFound::class)
    private fun findPrivateKeyAlias(keyStore: KeyStore): String {
        val aliases = keyStore.aliases()
        while (aliases.hasMoreElements()) {
            val alias = aliases.nextElement()
            if (keyStore.isKeyEntry(alias)) return alias
        }
        throw NoPrivateKeyFound()
    }

    @Throws(JSONException::class)
    private fun getErrorResponse(message: String, e: Exception): JSONObject {
        val response = JSONObject()
        response.put("success", false)
        response.put("message", message)
        response.put("exception", e)
        return response
    }
}
