package ru.ruNetSoft.crypto_pro_flutter

import android.content.Context
import android.content.pm.ApplicationInfo
import android.content.res.AssetManager
import android.os.Build
import androidx.annotation.RequiresApi
import androidx.documentfile.provider.DocumentFile
import org.bouncycastle.cert.X509CertificateHolder
import org.bouncycastle.cms.CMSException
import org.bouncycastle.cms.CMSProcessableByteArray
import org.bouncycastle.cms.CMSSignedData
import org.bouncycastle.util.Store
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
import ru.cprocsp.ACSP.tools.common.CSPTool
import ru.cprocsp.ACSP.tools.common.HexString
import ru.cprocsp.ACSP.tools.common.RawResource
import ru.cprocsp.ACSP.tools.license.CSPLicenseConstants
import ru.cprocsp.ACSP.tools.license.LicenseInterface
import ru.ruNetSoft.crypto_pro_flutter.exceptions.NoPrivateKeyFound
import java.io.*
import java.security.*
import java.security.cert.*
import java.security.cert.Certificate
import java.util.*
import javax.security.cert.CertificateException


/** Модуль для работы с Crypto Pro */
class CryptoProModule {
    companion object Factory {
        private var instance: CryptoProModule? = null
        private var trustCerts: ArrayList<X509Certificate> = ArrayList()
        private const val ROOT_CERTS_DIRECTORY = "root_certs"

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
                false
            } else {
                val containerFiles: ArrayList<DocumentFile> = ArrayList()
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

            chain.add(certificate)

            val cAdESSignature = CAdESSignature(detached, signHash)

            if (disableOnlineValidation) {
                cAdESSignature.setOptions((Options()).disableCertificateValidation());
            }

            var exception: Exception? = null;

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

            gfgThread.start()
            gfgThread.join();

            if (exception != null) {
                return getErrorResponse(exception.toString(), exception!!)
            }

            val signatureStream = ByteArrayOutputStream()

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

    fun checkCAdESCACertsAndInstall(
        context: Context
    ) {
        val trustStore = CSPConfig.getBksTrustStore() + File.separator +
                BKSTrustStore.STORAGE_FILE_TRUST

        // Пробуем взаимодействовать с assets
        val assetManager: AssetManager = context.assets
        val files =
            assetManager.list(ROOT_CERTS_DIRECTORY)

        if (files != null && !isAlreadyInstalled(trustStore)) {
            for (file in files) {
                val cert =
                    assetManager.open(ROOT_CERTS_DIRECTORY + File.separator + file)

                loadCert(cert, trustStore)
            }
        }

    }

    @RequiresApi(Build.VERSION_CODES.O)
    fun verifySignature(signedData: String?, signature: String, isDetached: Boolean): JSONObject {
        val responseJSON = JSONObject()

        var certsList: List<X509Certificate> = ArrayList()

        try {
            println("VERIFYSIGNATURE(): FUNC STARTED")
            certsList = getCertificateChain(signature, signedData)
            // Сертификаты (в данном случае корневой и пользователя,
            // выданный УЦ).
            val rootCertList: List<X509Certificate> = getRootCertsArray()
            val trust: MutableSet<TrustAnchor> = HashSet(0)

            println("VERIFYSIGNATURE(): ADD ALL ROOT CERTS TO TRUST")
            for (root in rootCertList) {
                trust.add(TrustAnchor(root, null))
            }

            // Сертификат пользователя
            val cert: ArrayList<Certificate> =
                ArrayList(0)

            cert.add(certsList[0])

            for (root in rootCertList) {
                cert.add(root)
            }

            println("VERIFYSIGNATURE(): PKIXBuilderParameters START")
            val cpp = PKIXBuilderParameters(trust, null)

            // Всегда используем только провайдер Java CSP.
            cpp.sigProvider = JCSP.PROVIDER_NAME

            val par = CollectionCertStoreParameters(cert)

            val store = CertStore.getInstance("Collection", par)
            cpp.addCertStore(store)

            val selector = X509CertSelector()
            selector.certificate = certsList[0]
            cpp.targetCertConstraints = selector

            // Построение цепочки, используем напрямую
            // {@link #PKIX_ALGORITHM}.
            println("VERIFYSIGNATURE(): BUILD CERTIFICATE CHAIN")
            cpp.isRevocationEnabled = false

            val builder: CertPathBuilder = CertPathBuilder.getInstance(
                "CPPKIX",
                "RevCheck"
            )

            val res = builder.build(cpp) as PKIXCertPathBuilderResult
            val cp = res.certPath

            // Проверка цепочки, используем напрямую
            // {@link #PKIX_ALGORITHM}.
            println("VERIFYSIGNATURE(): VERIFY CERTIFICATE CHAIN")

            val cpv: CertPathValidator = CertPathValidator.getInstance(
                "CPPKIX",
                "RevCheck"
            )

            cpp.isRevocationEnabled = true
            val pkixResult: CertPathValidatorResult = cpv.validate(cp, cpp)

            println("VERIFYSIGNATURE(): PKIX RESULT ${pkixResult.toString()}")

            responseJSON.put("success", true)
            responseJSON.put("result", true)

        }
        catch (e: Exception) {
            println("EXCEPTION : ${e.message}")
            responseJSON.put("success", false)
            responseJSON.put("message", e.message)
            responseJSON.put("result", false)
        } finally {
            // Создаем переменную, в которой будем хранить и передавать список сертификатов в JSON формате
            val certificatesJSON = ArrayList<JSONObject>()

            if (certsList.isNotEmpty()) {
                for((index, certificate) in certsList.withIndex()){
                    val certificateJSON = getJSONCertificate("signature_cert_${index + 1}", certificate)
                    certificatesJSON.add(certificateJSON)
                }
            }

            responseJSON.put("certificates", JSONArray(certificatesJSON))
        }


        return responseJSON
    }

    private fun getRootCertsArray(): List<X509Certificate> {
        val keyStore = KeyStore.getInstance(JCSP.HD_STORE_NAME, JCSP.PROVIDER_NAME)
        val certFactory = CertificateFactory.getInstance("X.509")
        val rootCertList: ArrayList<X509Certificate> = ArrayList(0)

        keyStore.load(null, null)
        val aliases: Enumeration<String> = keyStore.aliases()
        while (aliases.hasMoreElements()) {
            val alias = aliases.nextElement()
            if (keyStore.isCertificateEntry(alias)) {
                val tmpCert: Certificate = keyStore.getCertificate(alias)
                val cert =
                    certFactory.generateCertificate(ByteArrayInputStream(tmpCert.encoded)) as X509Certificate
                rootCertList.add(cert)
            } // if
        }

        return rootCertList
    }

    @RequiresApi(Build.VERSION_CODES.O)
    private fun getCertificateChain(signature: String, signedContent: String?): List<X509Certificate> {
        val convertedCertList: ArrayList<X509Certificate> = ArrayList()
        try {
            val certFactory = CertificateFactory.getInstance("X.509")
            var scBytes: ByteArray? = null
            val sigBytes: ByteArray = Base64.getDecoder().decode(signature.replace("\n", ""))

            if (signedContent != null) {
                scBytes = Base64.getDecoder().decode(signedContent.replace("\n", ""))
            }

            // Получаем массив сертификатов из отсоединенной подписи
            println("getCertificateChain(): GET SIGNED DATA FROM SIGNATURE START")
            var signedData: CMSSignedData? = null

            signedData = if (signedContent != null) {
                CMSSignedData(CMSProcessableByteArray(scBytes!!), sigBytes)
            } else {
                CMSSignedData(sigBytes)
            }


            println("getCertificateChain(): GET SIGNED DATA FROM SIGNATURE END")

            println("getCertificateChain(): GET CERTS START")
            val certs: Store<X509CertificateHolder> = signedData.certificates
            val listCerts: ArrayList<X509CertificateHolder> =
                ArrayList(certs.getMatches(null))

            if (listCerts.isNotEmpty()) {
                println("getCertificateChain(): RECEIVED CERTS AS STORE PROCEED TO CERT LIST")
                for (certificateHolder in listCerts) {
                    val `in`: InputStream = ByteArrayInputStream(certificateHolder.encoded)
                    val cert = certFactory.generateCertificate(`in`) as X509Certificate
                    convertedCertList.add(cert)
                }

                println("getCertificateChain(): CONVERTED CERTS LIST LENTH: ${convertedCertList.count()}")
            }

            println("getCertificateChain(): GET CERTS END")

        } catch (e: CertificateException) {
            println("getCertificateChain(): CertificateException ${e.printStackTrace()}")
//            e.printStackTrace()
        } catch (e: CMSException) {
            println("getCertificateChain(): CMSException ${e.printStackTrace()}")
        }
        return convertedCertList
    }



    @Throws(Exception::class)
    fun isAlreadyInstalled(trustStore: String): Boolean {
        val storeStream = FileInputStream(trustStore)
        val keyStore = KeyStore.getInstance(BKSTrustStore.STORAGE_TYPE)
        keyStore.load(
            storeStream,
            BKSTrustStore.STORAGE_PASSWORD
        )
        storeStream.close()

        // Если нет какого-то из сертификатов, то считается, что
        // они не установлены.
        if (trustCerts.isNotEmpty()) {
            for (crt in trustCerts) {
                if (keyStore.getCertificateAlias(crt) == null) {
                    return false
                } // if
            } // for
            return true
        } else {
            return false
        }
    }

    @Throws(Exception::class)
    private fun loadCert(trustStream: InputStream?, trustStore: String) {
        try {
            val factory = CertificateFactory.getInstance("X.509")
            trustCerts.add(factory.generateCertificate(trustStream) as X509Certificate)
        } finally {
            if (trustStream != null) {
                try {
                    trustStream.close()
                } catch (e: IOException) {
                }
            } // if

            if (trustCerts.isNotEmpty()) {
                for ((i, trustCert) in trustCerts.withIndex()) {
                    saveTrustCert(trustStore, getBksTrustStore(), trustCert)
                }
            }
        }
    }

    @Throws(Exception::class)
    private fun saveTrustCert(
        trustStore: String,
        trustStoreFile: File,
        trustCert: X509Certificate,
    ) {
        val storeStream = FileInputStream(trustStore)
        val keyStore = KeyStore.getInstance(BKSTrustStore.STORAGE_TYPE)
        keyStore.load(
            storeStream,
            BKSTrustStore.STORAGE_PASSWORD
        )
        storeStream.close()

        println(
            "Certificate sn: " +
                    HexString.toHex(trustCert.serialNumber.toByteArray(), true) +
                    ", subject: " + trustCert.subjectDN
        )

        // Будущий алиас корневого сертификата в хранилище.
        val trustCertAlias = HexString.toHex(trustCert.serialNumber.toByteArray(), true)

        // Вывод списка содержащищся в хранилище сертификатов.
        println("Current count of trusted certificates: " + keyStore.size())

        // Добавление сертификата, если его нет.
        val needAdd = (keyStore.getCertificateAlias(trustCert) == null)
        if (needAdd) {
            println(
                ("** Adding the trusted certificate " +
                        trustCert.subjectDN + " with alias '" +
                        trustCertAlias + "' into the trust store")
            )
            keyStore.setCertificateEntry(trustCertAlias, trustCert)
            val updatedTrustStore = FileOutputStream(trustStoreFile)
            keyStore.store(
                updatedTrustStore,
                BKSTrustStore.STORAGE_PASSWORD
            )
            println("The trusted certificate was added successfully.")
        } // if
        else {
            println(
                "** Trusted certificate has already " +
                        "existed in the trust store."
            )
        } // else
    }


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
