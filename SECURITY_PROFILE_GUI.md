
## 1.7 M5: スクリーンショット盗み見対策
- **オプトイン防護**: ユーザ設定（Privacy Mode）により、OS のキャプチャ防止 API を有効化。
  - Windows: `SetWindowDisplayAffinity` (WDA_EXCLUDEFROMCAPTURE)
  - macOS: `NSWindow.sharingType = .none`
- **限界の明記**: 本機能は OS レベルの標準的なキャプチャ（スクショ、録画、画面共有）を制限するものであり、物理的なカメラ撮影や低レイヤの不正プログラムによる取得を完全に防ぐものではない。
- **プラットフォーム制約**: Linux (X11/Wayland) 環境では OS/Compositor 側のセキュリティプロトコル（xdg-desktop-portal 等）に依存し、本アプリからの強制的な制限は行わない。
