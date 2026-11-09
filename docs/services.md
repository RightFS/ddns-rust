# 系统服务安装（`-s`）

`ddns-rust -s install`（长参数 `--service install`）将**当前二进制**注册成系统级服务，设置开机启动、立即在后台启动；等待 Web 健康检查就绪后，前台输出管理页地址并退出。不是普通后台 fork，也不需要额外的服务包装程序。支持 Windows SCM、Linux systemd 和 macOS launchd。

`ddns-rust -s uninstall`（`--service uninstall`）先停止后台服务，再删除系统服务注册/定义，并退出；保留二进制、DNS 配置、Web 管理员设置、凭据和日志。无需指定配置路径，配置不存在也可卸载。已卸载时再次卸载成功返回；停止失败时不会继续删除服务。单独 `-s` 或其他动作会报参数错误。

安装需要 Windows 管理员或 Unix root 权限。请先把二进制放在长期保留、仅管理员可修改的目录，再安装；服务保留其绝对路径，不会复制二进制。配置路径也转换为绝对路径，工作目录为配置所在目录，后续启动不依赖安装时的终端目录。配置目录须允许服务账号写入配置和 Web 设置，且不应允许不可信用户修改。默认服务以 LocalSystem/root 运行，可由管理员安装后调整为专用账号并授予必要权限。

```sh
cargo build --release
# Linux/macOS；默认 config.toml 相对于运行安装命令时的目录
sudo ./target/release/ddns-rust -s install
# 推荐显式指定已准备好的配置
sudo ./target/release/ddns-rust -s install --config /path/to/config.toml
# -s install 可放在 serve 前后；只有显式 --listen 才固定监听地址
sudo ./target/release/ddns-rust --config /path/to/config.toml serve -s install --listen 127.0.0.1:9876
```

```powershell
# 管理员 PowerShell，先将 exe 放到稳定目录
& 'C:\Program Files\ddns-rust\ddns-rust.exe' -s install --config 'C:\ProgramData\ddns-rust\config.toml'
```

配置不存在时沿用 `serve` 的首次启动行为：在既有父目录中生成无启用记录的安全配置；不会创建缺失的父目录。首次通过本机 Web 页面完成管理员初始化；默认监听 `127.0.0.1:9876`。已有 Web 设置也会沿用（保存在配置旁）。未提供 `--listen` 时遵循 Web 设置的监听地址。

`-s` 只允许默认命令或 `serve`，不能与 `init/check/diagnose/once` 混用。服务实际启动参数不包含 `-s`，不会递归安装。重复安装拒绝覆盖既有定义；改变配置路径/监听参数须显式停止、卸载再安装。仅替换同路径二进制后重启，无需重新安装。

## 安装输出与卸载

后台 Web 就绪后前台输出示例：

```text
Service installed and started in the background.
Web management: http://127.0.0.1:9876
```

地址优先使用 `serve --listen`，否则读取已有 Web 设置/默认地址。通配绑定 `0.0.0.0` / `::` 会输出可在本机访问的 `127.0.0.1` / `[::1]` 地址，而不是通配地址。没有显式 `--listen` 时，之后在页面修改监听地址并重启仍会生效。

```sh
# Linux/macOS：无需配置路径
sudo ./target/release/ddns-rust -s uninstall
```

```powershell
# 管理员 PowerShell
.\ddns-rust.exe -s uninstall
```

Linux 执行 stop、disable、删除 unit、daemon-reload；macOS 执行 bootout，等待原服务进程退出后删除 plist（最多 300 秒，不强杀其他进程）；Windows 等待服务 Stopped 后删除，并等待 SCM 注册消失。Windows 停止最多等 300 秒，删除确认最多等 30 秒；超时返回错误，不报告虚假成功。

## 环境变量与密钥

**系统服务不会继承安装终端里的 `export` / PowerShell 临时环境变量。**安装器不把当前环境变量或 `--token` 的值写入服务定义；若检测到 Web token 参数/环境覆盖，会提示其未被持久化。可直接使用 Web 管理员设置；若选择环境变量凭据或旧式 Bearer token，必须配置服务自身环境。更新环境后重启服务。

### Linux：systemd

- 服务名：`ddns-rust.service`
- 定义：`/etc/systemd/system/ddns-rust.service`
- 自动读取配置所在目录的可选 `ddns-rust.env`，不存在也允许启动。
- 开机随 `multi-user.target` 启动，网络就绪后启动；非正常退出自动重启。
- 日志使用 journald；停止时发送 SIGTERM，最多留 300 秒等待活动操作完成。

环境文件示例（systemd EnvironmentFile 格式，不写 `export`，不是 shell 脚本）：

```ini
TENCENT_SECRET_ID=your-secret-id
TENCENT_SECRET_KEY=your-secret-key
DDNS_RUST_WEB_TOKEN=your-random-token-at-least-24-characters
```

将环境文件权限设为 `600`，不要提交密钥到版本库。

```sh
sudo systemctl status ddns-rust
sudo journalctl -u ddns-rust -f
sudo systemctl restart ddns-rust
sudo systemctl stop ddns-rust
# 卸载（保留二进制、配置和凭据）
sudo systemctl disable --now ddns-rust
sudo rm /etc/systemd/system/ddns-rust.service
sudo systemctl daemon-reload
```

不支持未运行 systemd 的 Linux/普通容器，安装会明确报错。

### macOS：launchd

- 系统 LaunchDaemon：`com.ddns-rust`，不依赖用户登录。
- 定义：`/Library/LaunchDaemons/com.ddns-rust.plist`
- 日志：`/var/log/ddns-rust.log`，需按部署需求配置轮转。
- `RunAtLoad` 开机启动，非正常退出自动重启；停止宽限期 300 秒。

如果使用环境凭据，在 plist 顶层 `dict` 中显式增加 `EnvironmentVariables` 字典，然后重新加载：

```xml
<key>EnvironmentVariables</key>
<dict>
  <key>TENCENT_SECRET_ID</key><string>your-secret-id</string>
  <key>TENCENT_SECRET_KEY</key><string>your-secret-key</string>
</dict>
```

值中 XML 特殊字符须转义。含密钥时将 plist 设为 root 所有、权限 `600`，禁止其他账号读取，不要依赖终端环境或把密钥放进 `ProgramArguments`。

```sh
sudo launchctl print system/com.ddns-rust
sudo tail -f /var/log/ddns-rust.log
# 停止或修改 plist 后重载
sudo launchctl bootout system/com.ddns-rust
sudo launchctl bootstrap system /Library/LaunchDaemons/com.ddns-rust.plist
# 卸载（保留二进制、配置及日志）
sudo launchctl bootout system/com.ddns-rust
sudo rm /Library/LaunchDaemons/com.ddns-rust.plist
```

### Windows：原生 SCM 服务

- 服务名/显示名：`ddns-rust`，启动类型：自动。
- 默认服务账号：LocalSystem，不是安装时登录的用户。
- 隐藏内部参数 `--service-run` 连接 SCM；勿在终端手动使用。
- STOP/系统 SHUTDOWN 触发优雅退出，报告停止进度并等待正在进行的 DNS 操作；系统关机的原生超时仍可能强制终止进程，不保证无限等待。

使用环境变量时，须设置机器级/服务账号环境，不能只在当前 PowerShell 设置 `$env:...`。SCM 可能缓存机器环境；若重启服务仍读不到更新，需要重启 Windows。也可使用已支持的 Web 凭据设置，避免依赖 SCM 环境更新。服务没有交互控制台，运行日志可在 Web 日志页查看；启动失败查看 `sc.exe query` 的退出码及服务配置。

```powershell
sc.exe query ddns-rust
sc.exe qc ddns-rust
sc.exe stop ddns-rust
sc.exe start ddns-rust
# 卸载：等待服务停止后删除注册，保留二进制及配置
sc.exe delete ddns-rust
```

## 失败恢复与验证范围

安装定义成功但启动命令失败时，注册/文件可能已经保留，程序返回非零并输出失败步骤；先检查服务定义、配置权限、端口占用及环境，再用原生工具重启，或执行 `-s uninstall` 后重新安装，不会静默覆盖。安装命令还会等待 Web `/healthz` 最多 30 秒；未就绪会报告错误而不是安装成功。

测试覆盖参数校验、路径转义、服务启动参数不包含 `-s`、拒绝覆盖服务定义；CI 在 Linux、macOS、Windows 编译和运行测试。实际注册/开机/停止验收需要各平台有管理员权限的测试机器，不会在单元测试中修改宿主机服务。
