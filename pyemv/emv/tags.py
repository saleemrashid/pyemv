from enum import DynamicClassAttribute, Enum

from pyemv.tlv.ber import BerTag


class EMVTag(BerTag, Enum):
    def __init__(self, value: bytes, description: str):
        super().__init__(value)
        self._value_ = value
        self._description_ = description

    @DynamicClassAttribute
    def description(self) -> str:
        return self._description_

    def __repr__(self):
        return f"<{self.__class__.__name__}.{self.name}: {self.description!r}>"

    ACCOUNT_TYPE = b"\x5F\x57", "Account Type"
    ACQUIRER_IDENTIFIER = b"\x9F\x01", "Acquirer Identifier"
    ADDITIONAL_TERMINAL_CAPABILITIES = (
        b"\x9F\x40",
        "Additional Terminal Capabilities",
    )
    AMOUNT_AUTHORISED_NUMERIC = b"\x9F\x02", "Amount, Authorised (Numeric)"
    AMOUNT_OTHER_BINARY = b"\x9F\x04", "Amount, Other (Binary)"
    AMOUNT_OTHER_NUMERIC = b"\x9F\x03", "Amount, Other (Numeric)"
    AMOUNT_REFERENCE_CURRENCY = b"\x9F\x3A", "Amount, Reference Currency"
    APPLICATION_CRYPTOGRAM = b"\x9F\x26", "Application Cryptogram"
    APPLICATION_CURRENCY_CODE = b"\x9F\x42", "Application Currency Code"
    APPLICATION_CURRENCY_EXPONENT = (
        b"\x9F\x44",
        "Application Currency Exponent",
    )
    APPLICATION_DISCRETIONARY_DATA = (
        b"\x9F\x05",
        "Application Discretionary Data",
    )
    APPLICATION_EFFECTIVE_DATE = b"\x5F\x25", "Application Effective Date"
    APPLICATION_EXPIRATION_DATE = b"\x5F\x24", "Application Expiration Date"
    AFL = b"\x94", "Application File Locator (AFL)"
    ADF_NAME = b"\x4F", "Application Dedicated File (ADF) Name"
    AID_TERMINAL = b"\x9F\x06", "Application Identifier (AID) - terminal"
    APPLICATION_INTERCHANGE_PROFILE = (
        b"\x82",
        "Application Interchange Profile",
    )
    APPLICATION_LABEL = b"\x50", "Application Label"
    APPLICATION_PREFERRED_NAME = b"\x9F\x12", "Application Preferred Name"
    APPLICATION_PAN = b"\x5A", "Application Primary Account Number (PAN)"
    APPLICATION_PAN_SEQUENCE_NUMBER = (
        b"\x5F\x34",
        "Application Primary Account Number (PAN) Sequence Number",
    )
    APPLICATION_PRIORITY_INDICATOR = b"\x87", "Application Priority Indicator"
    APPLICATION_REFERENCE_CURRENCY = (
        b"\x9F\x3B",
        "Application Reference Currency",
    )
    APPLICATION_REFERENCE_CURRENCY_EXPONENT = (
        b"\x9F\x43",
        "Application Reference Currency Exponent",
    )
    APPLICATION_TEMPLATE = b"\x61", "Application Template"
    ATC = b"\x9F\x36", "Application Transaction Counter (ATC)"
    APPLICATION_USAGE_CONTROL = b"\x9F\x07", "Application Usage Control"
    APPLICATION_VERSION_NUMBER = b"\x9F\x08", "Application Version Number"
    APPLICATION_VERSION_NUMBER_TERMINAL = (
        b"\x9F\x09",
        "Application Version Number - terminal",
    )
    AUTHORISATION_CODE = b"\x89", "Authorisation Code"
    AUTHORISATION_RESPONSE_CODE = b"\x8A", "Authorisation Response Code"
    BIC = b"\x5F\x54", "Bank Identifier Code (BIC)"
    CDOL1 = b"\x8C", "Card Risk Management Data Object List 1 (CDOL1)"
    CDOL2 = b"\x8D", "Card Risk Management Data Object List 2 (CDOL2)"
    CARDHOLDER_NAME = b"\x5F\x20", "Cardholder Name"
    CARDHOLDER_NAME_EXTENDED = b"\x9F\x0B", "Cardholder Name Extended"
    CVM_LIST = b"\x8E", "Cardholder Verification Method (CVM) List"
    CVM_RESULTS = b"\x9F\x34", "Cardholder Verification Method (CVM) Results"
    CERTIFICATION_AUTHORITY_PUBLIC_KEY_INDEX = (
        b"\x8F",
        "Certification Authority Public Key Index",
    )
    CERTIFICATION_AUTHORITY_PUBLIC_KEY_INDEX_TERMINAL = (
        b"\x9F\x22",
        "Certification Authority Public Key Index - terminal",
    )
    COMMAND_TEMPLATE = b"\x83", "Command Template"
    CRYPTOGRAM_INFORMATION_DATA = b"\x9F\x27", "Cryptogram Information Data"
    DATA_AUTHENTICATION_CODE = b"\x9F\x45", "Data Authentication Code"
    DF_NAME = b"\x84", "Dedicated File (DF) Name"
    DDF_NAME = b"\x9D", "Directory Definition File (DDF) Name"
    DIRECTORY_DISCRETIONARY_TEMPLATE = (
        b"\x73",
        "Directory Discretionary Template",
    )
    DDOL = b"\x9F\x49", "Dynamic Data Authentication Data Object List (DDOL)"
    FCI_ISSUER_DISCRETIONARY_DATA = (
        b"\xBF\x0C",
        "File Control Information (FCI) Issuer Discretionary Data",
    )
    FCI_PROPRIETARY_TEMPLATE = (
        b"\xA5",
        "File Control Information (FCI) Proprietary Template",
    )
    FCI_TEMPLATE = b"\x6F", "File Control Information (FCI) Template"
    ICC_DYNAMIC_NUMBER = b"\x9F\x4C", "ICC Dynamic Number"
    ICC_PIN_ENCIPHERMENT_PUBLIC_KEY_CERTIFICATE = (
        b"\x9F\x2D",
        "Integrated Circuit Card (ICC) PIN Encipherment Public Key Certificate",
    )
    IFD_SERIAL_NUMBER = b"\x9F\x1E", "Interface Device (IFD) Serial Number"
    IBAN = b"\x5F\x53", "International Bank Account Number (IBAN)"
    ISSUER_ACTION_CODE_DEFAULT = b"\x9F\x0D", "Issuer Action Code - Default"
    ISSUER_ACTION_CODE_DENIAL = b"\x9F\x0E", "Issuer Action Code - Denial"
    ISSUER_ACTION_CODE_ONLINE = b"\x9F\x0F", "Issuer Action Code - Online"
    ISSUER_APPLICATION_DATA = b"\x9F\x10", "Issuer Application Data"
    ISSUER_AUTHENTICATION_DATA = b"\x91", "Issuer Authentication Data"
    ISSUER_CODE_TABLE_INDEX = b"\x9F\x11", "Issuer Code Table Index"
    ISSUER_COUNTRY_CODE = b"\x5F\x28", "Issuer Country Code"
    ISSUER_COUNTRY_CODE_ALPHA2_FORMAT = (
        b"\x5F\x55",
        "Issuer Country Code (alpha2 format)",
    )
    ISSUER_COUNTRY_CODE_ALPHA3_FORMAT = (
        b"\x5F\x56",
        "Issuer Country Code (alpha3 format)",
    )
    IIN = b"\x42", "Issuer Identification Number (IIN)"
    ISSUER_PUBLIC_KEY_CERTIFICATE = b"\x90", "Issuer Public Key Certificate"
    ISSUER_PUBLIC_KEY_EXPONENT = b"\x9F\x32", "Issuer Public Key Exponent"
    ISSUER_PUBLIC_KEY_REMAINDER = b"\x92", "Issuer Public Key Remainder"
    ISSUER_SCRIPT_COMMAND = b"\x86", "Issuer Script Command"
    ISSUER_SCRIPT_IDENTIFIER = b"\x9F\x18", "Issuer Script Identifier"
    ISSUER_SCRIPT_TEMPLATE_1 = b"\x71", "Issuer Script Template 1"
    ISSUER_SCRIPT_TEMPLATE_2 = b"\x72", "Issuer Script Template 2"
    ISSUER_URL = b"\x5F\x50", "Issuer URL"
    LANGUAGE_PREFERENCE = b"\x5F\x2D", "Language Preference"
    LAST_ONLINE_ATC_REGISTER = (
        b"\x9F\x13",
        "Last Online Application Transaction Counter (ATC) Register",
    )
    LOG_ENTRY = b"\x9F\x4D", "Log Entry"
    LOG_FORMAT = b"\x9F\x4F", "Log Format"
    LOWER_CONSECUTIVE_OFFLINE_LIMIT = (
        b"\x9F\x14",
        "Lower Consecutive Offline Limit",
    )
    MERCHANT_CATEGORY_CODE = b"\x9F\x15", "Merchant Category Code"
    MERCHANT_IDENTIFIER = b"\x9F\x16", "Merchant Identifier"
    MERCHANT_NAME_AND_LOCATION = b"\x9F\x4E", "Merchant Name and Location"
    PIN_TRY_COUNTER = (
        b"\x9F\x17",
        "Personal Identification Number (PIN) Try Counter",
    )
    POS_ENTRY_MODE = b"\x9F\x39", "Point-of-Service (POS) Entry Mode"
    PDOL = b"\x9F\x38", "Processing Options Data Object List (PDOL)"
    READ_RECORD_RESPONSE_MESSAGE_TEMPLATE = (
        b"\x70",
        "READ RECORD Response Message Template",
    )
    RESPONSE_MESSAGE_TEMPLATE_FORMAT_1 = (
        b"\x80",
        "Response Message Template Format 1",
    )
    RESPONSE_MESSAGE_TEMPLATE_FORMAT_2 = (
        b"\x77",
        "Response Message Template Format 2",
    )
    SERVICE_CODE = b"\x5F\x30", "Service Code"
    SFI = b"\x88", "Short File Identifier (SFI)"
    SIGNED_DYNAMIC_APPLICATION_DATA = (
        b"\x9F\x4B",
        "Signed Dynamic Application Data",
    )
    STATIC_DATA_AUTHENTICATION_TAG_LIST = (
        b"\x9F\x4A",
        "Static Data Authentication Tag List",
    )
    TERMINAL_CAPABILITIES = b"\x9F\x33", "Terminal Capabilities"
    TERMINAL_COUNTRY_CODE = b"\x9F\x1A", "Terminal Country Code"
    TERMINAL_IDENTIFICATION = b"\x9F\x1C", "Terminal Identification"
    TERMINAL_RISK_MANAGEMENT_DATA = (
        b"\x9F\x1D",
        "Terminal Risk Management Data",
    )
    TERMINAL_TYPE = b"\x9F\x35", "Terminal Type"
    TERMINAL_VERIFICATION_RESULTS = b"\x95", "Terminal Verification Results"
    TRACK_1_DISCRETIONARY_DATA = b"\x9F\x1F", "Track 1 Discretionary Data"
    TRACK_2_DISCRETIONARY_DATA = b"\x9F\x20", "Track 2 Discretionary Data"
    TRACK_2_EQUIVALENT_DATA = b"\x57", "Track 2 Equivalent Data"
    TDOL = b"\x97", "Transaction Certificate Data Object List (TDOL)"
    TC_HASH_VALUE = b"\x98", "Transaction Certificate (TC) Hash Value"
    TRANSACTION_CURRENCY_CODE = b"\x5F\x2A", "Transaction Currency Code"
    TRANSACTION_CURRENCY_EXPONENT = (
        b"\x5F\x36",
        "Transaction Currency Exponent",
    )
    TRANSACTION_DATE = b"\x9A", "Transaction Date"
    TRANSACTION_PIN_DATA = (
        b"\x99",
        "Transaction Personal Identification Number (PIN) Data",
    )
    TRANSACTION_REFERENCE_CURRENCY_CODE = (
        b"\x9F\x3C",
        "Transaction Reference Currency Code",
    )
    TRANSACTION_SEQUENCE_COUNTER = b"\x9F\x41", "Transaction Sequence Counter"
    TRANSACTION_STATUS_INFORMATION = b"\x9B", "Transaction Status Information"
    TRANSACTION_TIME = b"\x9F\x21", "Transaction Time"
    TRANSACTION_TYPE = b"\x9C", "Transaction Type"
    UNPREDICTABLE_NUMBER = b"\x9F\x37", "Unpredictable Number"
    UPPER_CONSECUTIVE_OFFLINE_LIMIT = (
        b"\x9F\x23",
        "Upper Consecutive Offline Limit",
    )
