package win32

//CryptSignMessage
//  [in]      PCRYPT_SIGN_MESSAGE_PARA pSignPara,
//  [in]      BOOL                     fDetachedSignature,
//  [in]      DWORD                    cToBeSigned,
//  [in]      const BYTE * []          rgpbToBeSigned,
//  [in]      DWORD []                 rgcbToBeSigned,
//  [out]     BYTE                     *pbSignedBlob,
//  [in, out] DWORD                    *pcbSignedBlob
func CryptSignMessage() (err error) {
	if r1, _, err := procCryptSignMessage.Call(); r1 == 0 {
		return err
	}
	return nil
}

//CryptVerifyMessageSignature
//  [in]            PCRYPT_VERIFY_MESSAGE_PARA pVerifyPara,
//  [in]            DWORD                      dwSignerIndex,
//  [in]            const BYTE                 *pbSignedBlob,
//  [in]            DWORD                      cbSignedBlob,
//  [out]           BYTE                       *pbDecoded,
//  [in, out]       DWORD                      *pcbDecoded,
//  [out, optional] PCCERT_CONTEXT             *ppSignerCert
func CryptVerifyMessageSignature() (err error) {
	if r1, _, err := procCryptVerifyMessageSignature.Call(); r1 == 0 {
		return err
	}
	return nil
}

//CryptVerifyDetachedMessageSignature
//  [in]            PCRYPT_VERIFY_MESSAGE_PARA pVerifyPara,
//  [in]            DWORD                      dwSignerIndex,
//  [in]            const BYTE                 *pbDetachedSignBlob,
//  [in]            DWORD                      cbDetachedSignBlob,
//  [in]            DWORD                      cToBeSigned,
//  [in]            const BYTE * []            rgpbToBeSigned,
//  [in]            DWORD []                   rgcbToBeSigned,
//  [out, optional] PCCERT_CONTEXT             *ppSignerCert
func CryptVerifyDetachedMessageSignature() (err error) {
	if r1, _, err := procCryptVerifyDetachedMessageSignature.Call(); r1 == 0 {
		return err
	}
	return nil
}

// CryptDecodeMessage
//  [in]                DWORD                       dwMsgTypeFlags,
//  [in]                PCRYPT_DECRYPT_MESSAGE_PARA pDecryptPara,
//  [in]                PCRYPT_VERIFY_MESSAGE_PARA  pVerifyPara,
//  [in]                DWORD                       dwSignerIndex,
//  [in]                const BYTE                  *pbEncodedBlob,
//  [in]                DWORD                       cbEncodedBlob,
//  [in]                DWORD                       dwPrevInnerContentType,
//  [out, optional]     DWORD                       *pdwMsgType,
//  [out, optional]     DWORD                       *pdwInnerContentType,
//  [out, optional]     BYTE                        *pbDecoded,
//  [in, out, optional] DWORD                       *pcbDecoded,
//  [out, optional]     PCCERT_CONTEXT              *ppXchgCert,
//  [out, optional]     PCCERT_CONTEXT              *ppSignerCert
func CryptDecodeMessage() (err error) {
	if r1, _, err := procCryptDecodeMessage.Call(); r1 == 0 {
		return err
	}
	return nil
}

// CryptEncryptMessage
//  [in]      PCRYPT_ENCRYPT_MESSAGE_PARA pEncryptPara,
//  [in]      DWORD                       cRecipientCert,
//  [in]      PCCERT_CONTEXT []           rgpRecipientCert,
//  [in]      const BYTE                  *pbToBeEncrypted,
//  [in]      DWORD                       cbToBeEncrypted,
//  [out]     BYTE                        *pbEncryptedBlob,
//  [in, out] DWORD                       *pcbEncryptedBlob
func CryptEncryptMessage() (err error) {
	if r1, _, err := procCryptEncryptMessage.Call(); r1 == 0 {
		return err
	}
	return nil
}

//CryptDecryptMessage
//  [in]                PCRYPT_DECRYPT_MESSAGE_PARA pDecryptPara,
//  [in]                const BYTE                  *pbEncryptedBlob,
//  [in]                DWORD                       cbEncryptedBlob,
//  [out, optional]     BYTE                        *pbDecrypted,
//  [in, out, optional] DWORD                       *pcbDecrypted,
//  [out, optional]     PCCERT_CONTEXT              *ppXchgCert
func CryptDecryptMessage() (err error) {
	if r1, _, err := procCryptDecryptMessage.Call(); r1 == 0 {
		return err
	}
	return nil
}

//CryptGetMessageCertificates HCERTSTORE
//  [in] DWORD             dwMsgAndCertEncodingType,
//  [in] HCRYPTPROV_LEGACY hCryptProv,
//  [in] DWORD             dwFlags,
//  [in] const BYTE        *pbSignedBlob,
//  [in] DWORD             cbSignedBlob
func CryptGetMessageCertificates() (err error) {
	if r1, _, err := procCryptGetMessageCertificates.Call(); r1 == 0 {
		return err
	}
	return nil
}

//CryptGetMessageSignerCount LONG
//[in] DWORD      dwMsgEncodingType,
//[in] const BYTE *pbSignedBlob,
//[in] DWORD      cbSignedBlob
func CryptGetMessageSignerCount() (err error) {
	if r1, _, err := procCryptGetMessageSignerCount.Call(); r1 == 0 {
		return err
	}
	return nil
}

//CryptHashMessage
//  [in]                PCRYPT_HASH_MESSAGE_PARA pHashPara,
//  [in]                BOOL                     fDetachedHash,
//  [in]                DWORD                    cToBeHashed,
//  [in]                const BYTE * []          rgpbToBeHashed,
//  [in]                DWORD []                 rgcbToBeHashed,
//  [out]               BYTE                     *pbHashedBlob,
//  [in, out]           DWORD                    *pcbHashedBlob,
//  [out, optional]     BYTE                     *pbComputedHash,
//  [in, out, optional] DWORD                    *pcbComputedHash
func CryptHashMessage() (err error) {
	if r1, _, err := procCryptHashMessage.Call(); r1 == 0 {
		return err
	}
	return nil
}

//CryptSignAndEncryptMessage
//  [in]      PCRYPT_SIGN_MESSAGE_PARA    pSignPara,
//  [in]      PCRYPT_ENCRYPT_MESSAGE_PARA pEncryptPara,
//  [in]      DWORD                       cRecipientCert,
//  [in]      PCCERT_CONTEXT []           rgpRecipientCert,
//  [in]      const BYTE                  *pbToBeSignedAndEncrypted,
//  [in]      DWORD                       cbToBeSignedAndEncrypted,
//  [out]     BYTE                        *pbSignedAndEncryptedBlob,
//  [in, out] DWORD                       *pcbSignedAndEncryptedBlob
func CryptSignAndEncryptMessage() (err error) {
	if r1, _, err := procCryptSignAndEncryptMessage.Call(); r1 == 0 {
		return err
	}
	return nil
}

//CryptSignMessageWithKey
//  [in]      PCRYPT_KEY_SIGN_MESSAGE_PARA pSignPara,
//  [in]      const BYTE                   *pbToBeSigned,
//  [in]      DWORD                        cbToBeSigned,
//  [out]     BYTE                         *pbSignedBlob,
//  [in, out] DWORD                        *pcbSignedBlob
func CryptSignMessageWithKey() (err error) {
	if r1, _, err := procCryptSignMessageWithKey.Call(); r1 == 0 {
		return err
	}
	return nil
}

//CryptMsgCalculateEncodedLength DWORD
//  [in]           DWORD      dwMsgEncodingType,
//  [in]           DWORD      dwFlags,
//  [in]           DWORD      dwMsgType,
//  [in]           void const *pvMsgEncodeInfo,
//  [in, optional] LPSTR      pszInnerContentObjID,
//  [in]           DWORD      cbData
//);
func CryptMsgCalculateEncodedLength() (err error) {
	if r1, _, err := procCryptMsgCalculateEncodedLength.Call(); r1 == 0 {
		return err
	}
	return nil
}

//CryptMsgOpenToEncode HCRYPTMSG
//  [in]           DWORD             dwMsgEncodingType,
//  [in]           DWORD             dwFlags,
//  [in]           DWORD             dwMsgType,
//  [in]           void const        *pvMsgEncodeInfo,
//  [in, optional] LPSTR             pszInnerContentObjID,
//  [in]           PCMSG_STREAM_INFO pStreamInfo
func CryptMsgOpenToEncode() (err error) {
	if r1, _, err := procCryptMsgOpenToEncode.Call(); r1 == 0 {
		return err
	}
	return nil
}

//CryptMsgOpenToDecode HCRYPTMSG
//  [in]           DWORD             dwMsgEncodingType,
//  [in]           DWORD             dwFlags,
//  [in]           DWORD             dwMsgType,
//  [in]           HCRYPTPROV_LEGACY hCryptProv,
//  [in]           PCERT_INFO        pRecipientInfo,
//  [in, optional] PCMSG_STREAM_INFO pStreamInfo
func CryptMsgOpenToDecode() (err error) {
	if r1, _, err := procCryptMsgOpenToDecode.Call(); r1 == 0 {
		return err
	}
	return nil
}

//CryptMsgUpdate
//  [in] HCRYPTMSG  hCryptMsg,
//  [in] const BYTE *pbData,
//  [in] DWORD      cbData,
//  [in] BOOL       fFinal
func CryptMsgUpdate() (err error) {
	if r1, _, err := procCryptMsgUpdate.Call(); r1 == 0 {
		return err
	}
	return nil
}

// CryptMsgGetParam BOOL CryptMsgGetParam(
//  [in]      HCRYPTMSG hCryptMsg,
//  [in]      DWORD     dwParamType,
//  [in]      DWORD     dwIndex,
//  [out]     void      *pvData,
//  [in, out] DWORD     *pcbData
func CryptMsgGetParam() (err error) {
	if r1, _, err := procCryptMsgGetParam.Call(); r1 == 0 {
		return err
	}
	return nil
}

// CryptMsgControl BOOL
//  [in] HCRYPTMSG  hCryptMsg,
//  [in] DWORD      dwFlags,
//  [in] DWORD      dwCtrlType,
//  [in] void const *pvCtrlPara
func CryptMsgControl() (err error) {
	if r1, _, err := procCryptMsgControl.Call(); r1 == 0 {
		return err
	}
	return nil
}

// CryptMsgClose
//  [in] HCRYPTMSG hCryptMsg
func CryptMsgClose() (err error) {
	if r1, _, err := procCryptMsgClose.Call(); r1 == 0 {
		return err
	}
	return nil
}

// CryptMsgDuplicate HCRYPTMSG
//  [in] HCRYPTMSG hCryptMsg
func CryptMsgDuplicate() (err error) {
	if r1, _, err := procCryptMsgDuplicate.Call(); r1 == 0 {
		return err
	}
	return nil
}
