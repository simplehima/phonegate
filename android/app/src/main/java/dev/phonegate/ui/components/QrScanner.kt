package dev.phonegate.ui.components

import android.Manifest
import android.content.pm.PackageManager
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.camera.core.CameraSelector
import androidx.camera.core.ImageAnalysis
import androidx.camera.core.ImageProxy
import androidx.camera.core.Preview
import androidx.camera.core.resolutionselector.ResolutionSelector
import androidx.camera.core.resolutionselector.ResolutionStrategy
import androidx.camera.lifecycle.ProcessCameraProvider
import androidx.camera.view.PreviewView
import androidx.compose.foundation.border
import androidx.compose.ui.draw.clipToBounds
import android.util.Size
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.aspectRatio
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.material3.Button
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.text.input.ImeAction
import androidx.compose.ui.unit.dp
import androidx.compose.ui.viewinterop.AndroidView
import androidx.core.content.ContextCompat
import androidx.lifecycle.compose.LocalLifecycleOwner
import com.google.zxing.BarcodeFormat
import com.google.zxing.BinaryBitmap
import com.google.zxing.DecodeHintType
import com.google.zxing.MultiFormatReader
import com.google.zxing.NotFoundException
import com.google.zxing.PlanarYUVLuminanceSource
import com.google.zxing.common.HybridBinarizer
import java.util.concurrent.Executors
import java.util.concurrent.atomic.AtomicBoolean

/** ZXing QR decoding of the camera's luminance plane (no Play Services / ML Kit). */
private class QrAnalyzer(private val onText: (String) -> Unit) : ImageAnalysis.Analyzer {
    private val reader = MultiFormatReader().apply {
        setHints(mapOf(DecodeHintType.POSSIBLE_FORMATS to listOf(BarcodeFormat.QR_CODE), DecodeHintType.TRY_HARDER to true))
    }
    private val done = AtomicBoolean(false)

    override fun analyze(image: ImageProxy) {
        try {
            if (done.get()) return
            val plane = image.planes[0]
            val buf = plane.buffer
            val rowStride = plane.rowStride
            val w = image.width
            val h = image.height
            val data = ByteArray(w * h)
            buf.rewind()
            if (rowStride == w) {
                buf.get(data, 0, w * h)
            } else {
                for (row in 0 until h) {
                    buf.position(row * rowStride)
                    buf.get(data, row * w, w)
                }
            }
            val source = PlanarYUVLuminanceSource(data, w, h, 0, 0, w, h, false)
            val result = try {
                reader.decodeWithState(BinaryBitmap(HybridBinarizer(source)))
            } catch (e: NotFoundException) {
                null
            } finally {
                reader.reset()
            }
            if (result != null && done.compareAndSet(false, true)) onText(result.text)
        } catch (e: Exception) {
            // A frame that cannot be read is simply skipped.
        } finally {
            image.close()
        }
    }
}

@Composable
private fun CameraPreview(onText: (String) -> Unit, modifier: Modifier) {
    val context = LocalContext.current
    val owner = LocalLifecycleOwner.current
    val executor = remember { Executors.newSingleThreadExecutor() }
    // COMPATIBLE renders through a TextureView, which scrolls, clips and stacks like any other view.
    // The default (a SurfaceView) is punched through the window and ignores Compose layout, so it
    // painted over the title bar and the controls around it.
    val previewView = remember {
        PreviewView(context).apply {
            implementationMode = PreviewView.ImplementationMode.COMPATIBLE
            scaleType = PreviewView.ScaleType.FILL_CENTER
        }
    }
    DisposableEffect(owner) {
        val future = ProcessCameraProvider.getInstance(context)
        var provider: ProcessCameraProvider? = null
        future.addListener({
            val p = future.get()
            provider = p
            val preview = Preview.Builder().build().also { it.surfaceProvider = previewView.surfaceProvider }
            // A dense QR shown on a monitor needs more than CameraX's 640x480 default to resolve.
            val hiRes = ResolutionSelector.Builder()
                .setResolutionStrategy(ResolutionStrategy(Size(1920, 1080), ResolutionStrategy.FALLBACK_RULE_CLOSEST_HIGHER_THEN_LOWER))
                .build()
            val analysis = ImageAnalysis.Builder()
                .setResolutionSelector(hiRes)
                .setBackpressureStrategy(ImageAnalysis.STRATEGY_KEEP_ONLY_LATEST)
                .build()
                .also { it.setAnalyzer(executor, QrAnalyzer { text -> ContextCompat.getMainExecutor(context).execute { onText(text) } }) }
            try {
                p.unbindAll()
                p.bindToLifecycle(owner, CameraSelector.DEFAULT_BACK_CAMERA, preview, analysis)
            } catch (e: Exception) {
                // No usable back camera; the paste fallback stays available.
            }
        }, ContextCompat.getMainExecutor(context))
        onDispose {
            provider?.unbindAll()
            executor.shutdown()
        }
    }
    AndroidView(factory = { previewView }, modifier = modifier)
}

/**
 * Camera QR scanner with a permission-denied state and a manual paste fallback, so a missing
 * or refused camera is never a dead end.
 */
@Composable
fun QrScanOrPaste(
    pasteLabel: String,
    pasteHint: String,
    scanDescription: String,
    onResult: (String) -> Unit,
) {
    val context = LocalContext.current
    var granted by remember {
        mutableStateOf(ContextCompat.checkSelfPermission(context, Manifest.permission.CAMERA) == PackageManager.PERMISSION_GRANTED)
    }
    var denied by rememberSaveable { mutableStateOf(false) }
    val launcher = rememberLauncherForActivityResult(ActivityResultContracts.RequestPermission()) { ok ->
        granted = ok
        denied = !ok
    }
    var pasted by rememberSaveable { mutableStateOf("") }

    Column {
        if (granted) {
            CameraPreview(
                onText = onResult,
                modifier = Modifier
                    .fillMaxWidth()
                    .aspectRatio(1f)
                    .clipToBounds()
                    .border(2.dp, MaterialTheme.colorScheme.outline, MaterialTheme.shapes.extraSmall)
                    .semantics { contentDescription = scanDescription },
            )
        } else {
            RecordSheet(Modifier.fillMaxWidth()) {
                Text(
                    if (denied) "Camera access is off, so the QR code can't be scanned. You can allow it, or paste the link below."
                    else "PhoneGate needs the camera only to read the QR code on your PC screen.",
                    style = MaterialTheme.typography.bodyLarge,
                )
                Gap(12.dp)
                Button(onClick = { launcher.launch(Manifest.permission.CAMERA) }, modifier = Modifier.heightIn(min = 48.dp)) {
                    Text("Allow camera")
                }
            }
        }
        Gap(16.dp)
        FormLabel(pasteLabel, color = MaterialTheme.colorScheme.onSurfaceVariant)
        Gap(4.dp)
        OutlinedTextField(
            value = pasted,
            onValueChange = { pasted = it.trim() },
            modifier = Modifier.fillMaxWidth(),
            placeholder = { Text(pasteHint) },
            singleLine = true,
            keyboardOptions = KeyboardOptions(imeAction = ImeAction.Done),
        )
        Gap(8.dp)
        OutlinedButton(onClick = { onResult(pasted) }, enabled = pasted.isNotEmpty(), modifier = Modifier.heightIn(min = 48.dp)) {
            Text("Use pasted text")
        }
    }
}
