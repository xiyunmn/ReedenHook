package com.xiyunmn.reedenhook.host

/**
 * Reference AOT / reverse-engineering constants from the Reeden 1.36.1 corpus
 * (Dart 3.10.7).
 *
 * Offsets are RVAs inside `lib/arm64-v8a/libapp.so` (image base 0).
 * Confirmed via blutter + IDA session `reeden01`.
 *
 * The active native unlock discovers current host RVAs and field-table slots at
 * runtime; these constants document the original analysis baseline. Pure Java
 * hooks cannot call into Dart AOT by themselves.
 */
object HostAot {
    const val LIB_APP: String = "libapp.so"
    const val LIB_FLUTTER: String = "libflutter.so"

    /** Dart SDK version from the 1.36.1 reference corpus. */
    const val DART_VERSION: String = "3.10.7"
    const val SNAPSHOT_HASH: String = "1ce86630892e2dca9a8543fdb8ed8e22"

    /** PurchasesUtil / CZc refresh entry (wrapper). */
    const val CZc_KWN: Long = 0x2248798L

    /** Real body of Kwn. */
    const val CZc_KWN_BODY: Long = 0x22487C4L

    /**
     * Generic setter that writes `*(obj + 0x27)`.
     * Primary unlock hook candidate (~80 callers).
     */
    const val CZc_SET_FIELD27: Long = 0x20F57A4L

    /** Active-state style closure of CZc. */
    const val CZc_ON_ACTIVE_STATE_CHANGE: Long = 0x18123BCL

    /**
     * THR.field_table_values slot for `CZc.Fwn` singleton.
     * Access: `*( *(THR + 0x78) + FWN_FIELD_TABLE_SLOT )`
     */
    const val FWN_FIELD_TABLE_SLOT: Long = 0x5268L

    /** THR.field_table_values slot for `CZc.Lo` notifier. */
    const val LO_FIELD_TABLE_SLOT: Long = 0x5260L

    /**
     * Instance offset of the pro / active boolean on `CZc.Fwn`.
     * Feature gates: load field then `tbz #4` (true -> premium path).
     */
    const val PRO_FLAG_INSTANCE_OFFSET: Long = 0x27L

    /** Logical static field offset for CZc.Fwn (0x2934 * 2 = 0x5268). */
    const val FWN_STATIC_OFFSET: Long = 0x2934L

    /**
     * License preference `loc.jbn` : eoc&lt;GZc, String&gt;.
     * Kwn reads this and copies GZc.field_f (valid) into Fwn.field_27.
     */
    const val LOC_JBN_STATIC_OFFSET: Long = 0x252CL
    const val LOC_JBN_FIELD_TABLE_SLOT: Long = 0x4A58L
    const val LOC_JBN_INIT: Long = 0xFC0150L
    const val LOC_JBN_DESERIALIZE: Long = 0xFC034CL
    const val LOC_JBN_SERIALIZE: Long = 0xFC0310L

    /** Kwn force-true binary patch sites from the 1.36.1 reference corpus. */
    const val KWN_BNE_FORCE_TRUE: Long = 0x224883CL
    const val KWN_ADD_FALSE_TO_TRUE: Long = 0x2248840L

    const val LICENSE_HOST: String = "https://license.reeden.app/api"
    const val LICENSE_HOST_CN: String = "https://license-cn.reeden.app/api"

    /** Synthetic license payload for local unlock research (GZc JSON keys). */
    const val FORGE_EMAIL: String = "reedenhook@local"
    const val FORGE_LICENSE_KEY: String = "RH-LOCAL-UNLOCK-1.37.1"
    const val FORGE_ORDER_ID: String = "reedenhook-local"
}
