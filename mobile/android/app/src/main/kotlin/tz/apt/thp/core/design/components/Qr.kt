package tz.apt.thp.core.design.components

import android.graphics.Bitmap
import androidx.compose.foundation.Image
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.runtime.Composable
import androidx.compose.runtime.remember
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.asImageBitmap
import androidx.compose.ui.platform.LocalDensity
import androidx.compose.ui.unit.Dp
import androidx.compose.ui.unit.dp
import com.google.zxing.BarcodeFormat
import com.google.zxing.EncodeHintType
import com.google.zxing.qrcode.QRCodeWriter
import com.google.zxing.qrcode.decoder.ErrorCorrectionLevel
import tz.apt.thp.core.design.Radii

/**
 * Renders [text] as a QR code locally via zxing-core. Critical: NEVER offload
 * QR rendering to a public encoder — the install URL carries a plaintext
 * single-use token. Tanzania-data-residency + token-leak hygiene.
 */
@Composable
fun Qr(
    text: String,
    modifier: Modifier = Modifier,
    size: Dp = 220.dp,
) {
    val density = LocalDensity.current
    val pxSize = with(density) { size.toPx().toInt().coerceAtLeast(1) }
    val bitmap = remember(text, pxSize) { generateQrBitmap(text, pxSize) }
    Box(
        modifier = modifier
            .size(size)
            .clip(RoundedCornerShape(Radii.input))
            .background(Color.White),
    ) {
        Image(
            bitmap = bitmap.asImageBitmap(),
            contentDescription = "QR for install URL",
            modifier = Modifier.size(size),
        )
    }
}

private fun generateQrBitmap(text: String, sizePx: Int): Bitmap {
    val hints = mapOf(
        EncodeHintType.ERROR_CORRECTION to ErrorCorrectionLevel.M,
        EncodeHintType.MARGIN to 1,
    )
    val matrix = QRCodeWriter().encode(text, BarcodeFormat.QR_CODE, sizePx, sizePx, hints)
    val w = matrix.width
    val h = matrix.height
    val pixels = IntArray(w * h)
    for (y in 0 until h) {
        for (x in 0 until w) {
            pixels[y * w + x] = if (matrix.get(x, y)) android.graphics.Color.BLACK
                                else android.graphics.Color.WHITE
        }
    }
    return Bitmap.createBitmap(pixels, w, h, Bitmap.Config.ARGB_8888)
}
