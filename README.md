実装済みの防御機能
1. IP Address Filtering 
概要: 認証処理が走る前に、接続元IPアドレスをチェック

対象: /admin/**

挙動: 対象外のIPからのアクセスは、認証画面スキップし 403 Forbidden (JSON) で即座に遮断

実装クラス: IpAddressFilter (Custom OncePerRequestFilter)

2. Brute Force Protection (Account Lockout)
概要: 同一ユーザーによる連続ログイン失敗を監視し、攻撃を無効化します。

仕様:

5回連続失敗でアカウントをロック。

ロック期間は1分間（自動解除機能付き）

実装: AuthenticationEvents (EventListener) と UserDetailsService の連携

3. Custom Exception Handling (API Friendly)
概要: エラーレスポンスをブラウザのリダイレクトではなくJSONで制御

ハンドリング内容:

ログイン失敗（AuthenticationFailureHandler）

権限不足（AccessDeniedHandler）

IP制限（Custom Filter Response）

4. Real-time Security Monitoring
概要: 全ての認証成功・失敗イベントをキャッチし、サーバーログに詳細を表示

ログ形式: SUCCESS: ユーザー [user] がログインしました。 / FAILURE: ユーザー [user] ログイン失敗 (3/5)
