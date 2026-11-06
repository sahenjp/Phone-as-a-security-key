import AVFoundation
import SwiftUI
import UIKit

// MARK: - QR ペイロード検証
//
// PC 側 (iphone-fido pair-qr) が表示する QR コードの中身は
//   phonefido-pair:1:<Base32 52 文字>
// という固定形式。接頭辞が完全一致し、残りが正規 Base32 で
// ちょうど 32 byte に復号できる場合だけペアリングシークレットとして扱う。

enum PairingQRPayload {
    static let prefix = "phonefido-pair:1:"
    static let codeLength = 52

    static func parse(_ raw: String) -> Data? {
        guard raw.hasPrefix(prefix) else { return nil }
        let code = String(raw.dropFirst(prefix.count))
        guard code.count == codeLength else { return nil }
        guard let secret = CryptoUtils.base32DecodeNoPadding(code),
              secret.count == 32
        else { return nil }
        return secret
    }
}

// MARK: - QR ペアリング画面
//
// 読み取り → SAS 確認 → 保存、の 3 状態を持つシート。
// 保存するまで Keychain には一切触らない。キャンセルは何も残さない。

struct QRPairingView: View {
    @EnvironmentObject private var appState: AppState
    @Environment(\.dismiss) private var dismiss

    /// 読み取り済みのシークレット。非 nil の間は確認画面を出す。
    @State private var scannedSecret: Data?
    @State private var showInvalidCodeAlert = false
    @State private var cameraUnavailable = false
    @State private var saveFailed = false
    /// 不正なコードを読んだあと、スキャナを作り直して再開するための ID。
    @State private var scannerID = UUID()

    var body: some View {
        NavigationStack {
            Group {
                if let secret = scannedSecret {
                    confirmationView(secret: secret)
                } else if cameraUnavailable {
                    cameraUnavailableView
                } else {
                    scannerView
                }
            }
            .navigationTitle("pairing.qr.title")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button("common.cancel") { dismiss() }
                }
            }
            .alert(
                "pairing.qr.invalid_code",
                isPresented: $showInvalidCodeAlert
            ) {
                Button("common.ok", role: .cancel) {
                    // スキャナを再構築して読み取りを再開する
                    scannerID = UUID()
                }
            }
        }
    }

    // MARK: 読み取り

    private var scannerView: some View {
        ZStack(alignment: .bottom) {
            QRCodeScannerView(
                onCodeScanned: { raw in
                    if let secret = PairingQRPayload.parse(raw) {
                        scannedSecret = secret
                    } else {
                        showInvalidCodeAlert = true
                    }
                },
                onCameraUnavailable: {
                    cameraUnavailable = true
                }
            )
            .id(scannerID)
            .ignoresSafeArea()

            Text("pairing.qr.scanner_instruction")
                .font(.footnote)
                .multilineTextAlignment(.center)
                .padding(12)
                .background(.ultraThinMaterial, in: RoundedRectangle(cornerRadius: 12))
                .padding()
        }
    }

    // MARK: カメラ不可

    private var cameraUnavailableView: some View {
        VStack(spacing: 16) {
            Image(systemName: "camera.slash")
                .font(.system(size: 40))
                .foregroundStyle(.secondary)
            Text("pairing.qr.camera_unavailable")
                .multilineTextAlignment(.center)
                .foregroundStyle(.secondary)
            Button("common.ok") { dismiss() }
                .buttonStyle(.bordered)
        }
        .padding(24)
    }

    // MARK: 確認

    private func confirmationView(secret: Data) -> some View {
        VStack(spacing: 24) {
            Image(systemName: "qrcode.viewfinder")
                .font(.system(size: 40))
                .foregroundStyle(.blue)
                .frame(width: 88, height: 88)
                .background(.ultraThinMaterial, in: Circle())

            Text("pairing.qr.confirm_title")
                .font(.title2)
                .bold()

            VStack(spacing: 8) {
                Text("pairing.sas_label")
                    .font(.caption)
                    .foregroundStyle(.secondary)
                Text(CryptoUtils.sasCode(for: secret))
                    .font(.system(.largeTitle, design: .monospaced))
                    .bold()
            }

            Text("pairing.qr.confirm_message")
                .font(.footnote)
                .foregroundStyle(.secondary)
                .multilineTextAlignment(.center)

            if saveFailed {
                Text("pairing.qr.save_failed")
                    .font(.footnote)
                    .foregroundStyle(.red)
                    .multilineTextAlignment(.center)
            }

            VStack(spacing: 12) {
                Button {
                    if appState.savePairingSecret(secret) {
                        dismiss()
                    } else {
                        saveFailed = true
                    }
                } label: {
                    Text("pairing.qr.save")
                        .frame(maxWidth: .infinity)
                }
                .buttonStyle(.borderedProminent)
                .controlSize(.large)

                Button(role: .destructive) {
                    dismiss()
                } label: {
                    Text("common.cancel")
                        .frame(maxWidth: .infinity)
                }
                .buttonStyle(.bordered)
                .controlSize(.large)
            }
        }
        .padding(24)
    }
}

// MARK: - カメラスキャナ (AVFoundation)
//
// AVCaptureSession + メタデータ出力で QR だけを読む。
// 最初の 1 件を報告したらセッションを止める (再開は View の作り直し)。
// カメラが使えない (権限なし / ハードウェアなし) 場合は
// onCameraUnavailable で上位に伝える。

private struct QRCodeScannerView: UIViewControllerRepresentable {
    let onCodeScanned: (String) -> Void
    let onCameraUnavailable: () -> Void

    func makeUIViewController(context: Context) -> QRScannerViewController {
        let controller = QRScannerViewController()
        controller.onCodeScanned = onCodeScanned
        controller.onCameraUnavailable = onCameraUnavailable
        return controller
    }

    func updateUIViewController(
        _ uiViewController: QRScannerViewController,
        context: Context
    ) {}
}

private final class QRScannerViewController: UIViewController,
    AVCaptureMetadataOutputObjectsDelegate
{
    var onCodeScanned: ((String) -> Void)?
    var onCameraUnavailable: (() -> Void)?

    private let session = AVCaptureSession()
    private let sessionQueue = DispatchQueue(label: "iphone-fido.qr-scanner")
    private var previewLayer: AVCaptureVideoPreviewLayer?
    private var isConfigured = false
    private var didReportCode = false

    override func viewDidLoad() {
        super.viewDidLoad()
        view.backgroundColor = .black
        switch AVCaptureDevice.authorizationStatus(for: .video) {
        case .authorized:
            configureSession()
        case .notDetermined:
            AVCaptureDevice.requestAccess(for: .video) { [weak self] granted in
                guard let self else { return }
                if granted {
                    self.configureSession()
                } else {
                    DispatchQueue.main.async { self.onCameraUnavailable?() }
                }
            }
        case .denied, .restricted:
            onCameraUnavailable?()
        @unknown default:
            onCameraUnavailable?()
        }
    }

    override func viewWillAppear(_ animated: Bool) {
        super.viewWillAppear(animated)
        sessionQueue.async { [weak self] in
            guard let self, self.isConfigured, !self.session.isRunning else { return }
            self.session.startRunning()
        }
    }

    override func viewWillDisappear(_ animated: Bool) {
        super.viewWillDisappear(animated)
        sessionQueue.async { [weak self] in
            guard let self, self.session.isRunning else { return }
            self.session.stopRunning()
        }
    }

    override func viewDidLayoutSubviews() {
        super.viewDidLayoutSubviews()
        previewLayer?.frame = view.bounds
    }

    private func configureSession() {
        sessionQueue.async { [weak self] in
            guard let self, !self.isConfigured else { return }
            guard
                let device = AVCaptureDevice.default(for: .video),
                let input = try? AVCaptureDeviceInput(device: device),
                self.session.canAddInput(input)
            else {
                DispatchQueue.main.async { self.onCameraUnavailable?() }
                return
            }
            self.session.addInput(input)

            let output = AVCaptureMetadataOutput()
            guard self.session.canAddOutput(output) else {
                DispatchQueue.main.async { self.onCameraUnavailable?() }
                return
            }
            self.session.addOutput(output)
            output.setMetadataObjectsDelegate(self, queue: DispatchQueue.main)
            output.metadataObjectTypes = [.qr]
            self.isConfigured = true

            DispatchQueue.main.async {
                let preview = AVCaptureVideoPreviewLayer(session: self.session)
                preview.videoGravity = .resizeAspectFill
                preview.frame = self.view.bounds
                self.view.layer.addSublayer(preview)
                self.previewLayer = preview
            }
            if !self.session.isRunning {
                self.session.startRunning()
            }
        }
    }

    func metadataOutput(
        _ output: AVCaptureMetadataOutput,
        didOutput metadataObjects: [AVMetadataObject],
        from connection: AVCaptureConnection
    ) {
        guard
            !didReportCode,
            let object = metadataObjects.first as? AVMetadataMachineReadableCodeObject,
            object.type == .qr,
            let value = object.stringValue
        else { return }
        didReportCode = true
        sessionQueue.async { [weak self] in
            guard let self, self.session.isRunning else { return }
            self.session.stopRunning()
        }
        onCodeScanned?(value)
    }
}
