using Microsoft.Win32;
using System;
using System.Collections.Generic;
using System.Diagnostics; // 用于获取当前进程的exe路径
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Reflection;
using System.Text.Json;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using System.Web;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Documents;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using System.Windows.Threading;

namespace TUST_gateway_authentication
{
    public static class StringExtensions
    {
        public static int? ToInt(this string input)
        {
            if (int.TryParse(input, out int result))
                return result;
            return null;
        }
    }

    public partial class MainWindow : Window
    {
        private HttpClient client = new HttpClient();
        private DispatcherTimer authTimer;
        private const string SettingsFilePath = "app_settings.json";
        private const int MaxLogLines = 30;
        private int authOnlineInterval = 30;
        private int authOfflineInterval = 5;
        private string group1LatestStatus = "未开始";
        private string group2LatestStatus = "未启用";
        private bool isAutoAuthRequested = false;
        private bool ipGroup2Added = false;

        public MainWindow()
        {
            InitializeComponent();
            InitializeLogoutLink();
            SetupHttpClient();
            InitializeAuthTimer();
            LoadLastUsedSettings();
            CheckAutoStartSetting();
            ApplyUISettings();

            // 事件处理
            chkShowIPv6.Checked += (s, e) => ApplyUISettings();
            chkShowIPv6.Unchecked += (s, e) => ApplyUISettings();
            chkShowTerminalType.Checked += (s, e) => ApplyUISettings();
            chkShowTerminalType.Unchecked += (s, e) => ApplyUISettings();
            chkDistinguishGroups.Checked += (s, e) => ApplyUISettings();
            chkDistinguishGroups.Unchecked += (s, e) => ApplyUISettings();

            // 新增：初始化托盘菜单文本和图标
            UpdateTrayAuthMenuText();
            UpdateTrayIcon();
        }

        #region Initialization Methods
        private void InitializeLogoutLink()
        {
            lnkLogout.MouseEnter += (s, e) => lnkLogout.Foreground = Brushes.DarkBlue;
            lnkLogout.MouseLeave += (s, e) => lnkLogout.Foreground = Brushes.Blue;
        }

        private void SetupHttpClient()
        {
            client.DefaultRequestHeaders.UserAgent.ParseAdd("Mozilla/5.0 (Windows NT 10.0; Win64; x64)");
            client.Timeout = TimeSpan.FromSeconds(30);
        }

        private void InitializeAuthTimer()
        {
            authTimer = new DispatcherTimer();
            authTimer.Interval = TimeSpan.FromSeconds(authOnlineInterval);
            authTimer.Tick += async (s, e) => await SendAuthRequest();
        }

        private void ApplyUISettings()
        {
            // IPv6 可见性
            bool showIPv6 = chkShowIPv6.IsChecked == true;
            txtIpv6Label1.Visibility = showIPv6 ? Visibility.Visible : Visibility.Collapsed;
            txtWlanUserIpv6.Visibility = showIPv6 ? Visibility.Visible : Visibility.Collapsed;
            txtIpv6Label2.Visibility = showIPv6 && ipGroup2Added ? Visibility.Visible : Visibility.Collapsed;
            txtWlanUserIpv6_2.Visibility = showIPv6 && ipGroup2Added ? Visibility.Visible : Visibility.Collapsed;
            txtIpv4Label2.Visibility = ipGroup2Added ? Visibility.Visible : Visibility.Collapsed;

            // 终端类型可见性
            bool showTerminal = chkShowTerminalType.IsChecked == true;
            bool distinguishGroups = chkDistinguishGroups.IsChecked == true;

            // 更新控件可见性
            unifiedOperatorGroup.Visibility = showTerminal && !distinguishGroups ?
                Visibility.Visible : Visibility.Collapsed;

            group1OperatorPanel.Visibility = showTerminal && distinguishGroups ?
                Visibility.Visible : Visibility.Collapsed;

            group2OperatorPanel.Visibility = showTerminal && distinguishGroups && ipGroup2Added ?
                Visibility.Visible : Visibility.Collapsed;
        }
        #endregion

        #region Network Methods
        private NetworkInterface GetBestNetworkInterface()
        {
            try
            {
                return NetworkInterface.GetAllNetworkInterfaces()
                    .Where(nic => nic.OperationalStatus == OperationalStatus.Up)
                    .Where(nic => nic.NetworkInterfaceType != NetworkInterfaceType.Loopback &&
                                  nic.NetworkInterfaceType != NetworkInterfaceType.Tunnel &&
                                  !nic.Name.Contains("Virtual") &&
                                  !nic.Name.Contains("VMware") &&
                                  !nic.Name.Contains("Hyper-V"))
                    .OrderByDescending(nic => nic.GetIPProperties().GatewayAddresses.Any())
                    .ThenByDescending(nic => nic.GetIPv4Statistics().BytesReceived > 0)
                    .ThenByDescending(nic => nic.NetworkInterfaceType == NetworkInterfaceType.Wireless80211)
                    .FirstOrDefault();
            }
            catch (Exception ex)
            {
                UpdateStatus($"获取网络接口错误: {ex.Message}");
                return null;
            }
        }

        private (string ipv4, string ipv6) GetPreferredNetworkIPs()
        {
            var nic = GetBestNetworkInterface();
            if (nic == null) return (GetFallbackIPv4(), GetFallbackIPv6());

            try
            {
                string bestIPv4 = nic.GetIPProperties().UnicastAddresses
                    .Where(addr => addr.Address.AddressFamily == AddressFamily.InterNetwork)
                    .Select(addr => addr.Address.ToString())
                    .FirstOrDefault() ?? string.Empty;

                string bestIPv6 = nic.GetIPProperties().UnicastAddresses
                    .Where(addr => addr.Address.AddressFamily == AddressFamily.InterNetworkV6)
                    .Where(addr => !addr.Address.IsIPv6LinkLocal)
                    .Select(addr => addr.Address.ToString())
                    .FirstOrDefault() ?? string.Empty;

                return (bestIPv4, bestIPv6);
            }
            catch (Exception ex)
            {
                UpdateStatus($"获取首选IP错误: {ex.Message}");
                return (GetFallbackIPv4(), GetFallbackIPv6());
            }
        }

        private string GetFallbackIPv4()
        {
            try
            {
                return Dns.GetHostEntry(Dns.GetHostName()).AddressList
                    .FirstOrDefault(ip => ip.AddressFamily == AddressFamily.InterNetwork)?
                    .ToString() ?? "10.0.0.1";
            }
            catch { return "10.0.0.1"; }
        }

        private string GetFallbackIPv6()
        {
            try
            {
                return Dns.GetHostEntry(Dns.GetHostName()).AddressList
                    .FirstOrDefault(ip => ip.AddressFamily == AddressFamily.InterNetworkV6)?
                    .ToString() ?? "::1";
            }
            catch { return "::1"; }
        }

        private bool IsCurrentActiveIP(string ipString)
        {
            if (string.IsNullOrWhiteSpace(ipString)) return true;

            try
            {
                var nic = GetBestNetworkInterface();
                if (nic == null) return false;

                return nic.GetIPProperties().UnicastAddresses
                    .Any(addr => addr.Address.ToString().Equals(ipString));
            }
            catch (Exception ex)
            {
                UpdateStatus($"IP检查错误: {ex.Message}");
                return false;
            }
        }
        #endregion

        #region UI Control Methods
        private void lnkAddIPGroup_Click(object sender, RoutedEventArgs e)
        {
            if (!ipGroup2Added)
            {
                // 显示第二组
                txtWlanUserIp2.Visibility = Visibility.Visible;
                sepIPGroupDivider.Visibility = Visibility.Visible;
                txtGroup2Status.Visibility = Visibility.Visible;

                ((Run)lnkAddIPGroup.Inlines.FirstInline).Text = "-";
                ipGroup2Added = true;
            }
            else
            {
                // 隐藏第二组
                txtWlanUserIp2.Visibility = Visibility.Collapsed;
                sepIPGroupDivider.Visibility = Visibility.Collapsed;
                txtGroup2Status.Visibility = Visibility.Collapsed;

                ((Run)lnkAddIPGroup.Inlines.FirstInline).Text = "+";
                ipGroup2Added = false;
                UpdateGroupStatus(2, "禁用");
            }
            ApplyUISettings();
        }

        private void ToggleAuthTimer(bool enable)
        {
            if (enable)
            {
                // Update authentication intervals
                if (int.TryParse(txtOnlineInterval.Text, out int onlineInterval) && onlineInterval > 0)
                    authOnlineInterval = onlineInterval;
                if (int.TryParse(txtOfflineInterval.Text, out int offlineInterval) && offlineInterval > 0)
                    authOfflineInterval = offlineInterval;

                authTimer.Interval = TimeSpan.FromSeconds(authOnlineInterval);
                authTimer.Start();
                SetControlsState(false);
                UpdateStatus("启动认证循环");
            }
            else
            {
                authTimer.Stop();
                SetControlsState(true);
                UpdateStatus("终止认证循环");
            }
            // 同步托盘菜单和图标状态
            UpdateTrayAuthMenuText();
            UpdateTrayIcon();
        }

        private void SetControlsState(bool enabled)
        {
            // Account and connection controls
            txtAccount.IsEnabled = enabled;
            txtPassword.IsEnabled = enabled;
            txtLoginMethod.IsEnabled = enabled;
            txtCallback.IsEnabled = enabled;
            txtWlanUserIp.IsEnabled = enabled;
            txtWlanUserIpv6.IsEnabled = enabled;
            txtWlanUserMac.IsEnabled = enabled;
            txtWlanAcIp.IsEnabled = enabled;
            txtJsVersion.IsEnabled = enabled;
            txtV.IsEnabled = enabled;
            txtAuthGateway.IsEnabled = enabled;
            txtTerminalType.IsEnabled = enabled;
            txtWlanVlanId.IsEnabled = enabled;
            txtLogoutAccount.IsEnabled = enabled;
            txtLogoutPassword.IsEnabled = enabled;
            txtAcLogout.IsEnabled = enabled;
            chkSavePassword.IsEnabled = enabled;
            btnRefreshIPs.IsEnabled = enabled;


            // IP controls
            txtOnlineInterval.IsEnabled = enabled;
            txtOfflineInterval.IsEnabled = enabled;
            chkAutoStart.IsEnabled = enabled;

            // Group-related controls
            lnkAddIPGroup.IsEnabled = enabled;
            txtWlanUserIp2.IsEnabled = enabled && ipGroup2Added;
            txtWlanUserIpv6_2.IsEnabled = enabled && ipGroup2Added;

            // Configuration controls
            chkShowIPv6.IsEnabled = enabled;
            chkShowTerminalType.IsEnabled = enabled;
            chkDistinguishGroups.IsEnabled = enabled;

            // Group-specific operators
            cmbGroup1TerminalType.IsEnabled = enabled;
            cmbGroup1Operator.IsEnabled = enabled;
            cmbGroup2TerminalType.IsEnabled = enabled && ipGroup2Added;
            cmbGroup2Operator.IsEnabled = enabled && ipGroup2Added;

            // Unified operators
            cmbTerminalType.IsEnabled = enabled;
            cmbOperator.IsEnabled = enabled;

            btnLogin.Content = enabled ? "开始维持认证" : "停止维持认证";
        }


        #endregion

        #region Settings Management
        private void SaveLastUsedSettings()
        {
            try
            {
                File.WriteAllText(SettingsFilePath, JsonSerializer.Serialize(
                    new AppSettings
                    {
                        LastAccount = txtAccount.Text,
                        LastPassword = txtPassword.Password,
                        LastCallback = txtCallback.Text,
                        LastLoginMethod = txtLoginMethod.Text,
                        LastWlanUserIp = txtWlanUserIp.Text,
                        LastWlanUserIpv6 = txtWlanUserIpv6.Text,
                        LastWlanUserMac = txtWlanUserMac.Text,
                        LastWlanAcIp = txtWlanAcIp.Text,
                        LastAuthGateway = txtAuthGateway.Text,
                        LastTerminalType = txtTerminalType.Text,
                        LastWlanVlanId = txtWlanVlanId.Text,
                        LastLogoutAccount = txtLogoutAccount.Text,
                        LastLogoutPassword = txtLogoutPassword.Text,
                        LastAcLogout = txtAcLogout.Text,
                        LastJsVersion = txtJsVersion.Text,
                        LastV = txtV.Text,
                        LastOperatorIndex = cmbOperator.SelectedIndex,
                        LastSavePassword = chkSavePassword.IsChecked ?? false,
                        OnlineInterval = authOnlineInterval,
                        OfflineInterval = authOfflineInterval,
                        AutoStartEnabled = chkAutoStart.IsChecked ?? false,
                        TerminalTypeIndex = cmbTerminalType.SelectedIndex,
                        LastWlanUserIp2 = txtWlanUserIp2.Text,
                        LastWlanUserIpv6_2 = txtWlanUserIpv6_2.Text,
                        AutoAuthEnabled = chkAutoAuth.IsChecked ?? false,

                        // New settings
                        ShowIPv6 = chkShowIPv6.IsChecked ?? false,
                        ShowTerminalType = chkShowTerminalType.IsChecked ?? true,
                        DistinguishGroups = chkDistinguishGroups.IsChecked ?? false,
                        Group1OperatorIndex = cmbGroup1Operator.SelectedIndex,
                        Group1TerminalTypeIndex = cmbGroup1TerminalType.SelectedIndex,
                        Group2OperatorIndex = cmbGroup2Operator.SelectedIndex,
                        Group2TerminalTypeIndex = cmbGroup2TerminalType.SelectedIndex,
                        AutoHideOnStartEnabled = chkAutoHideOnStart.IsChecked ?? false
                    },
                    new JsonSerializerOptions { WriteIndented = true }
                ));
                UpdateStatus("参数设置已保存");
            }
            catch (Exception ex)
            {
                UpdateStatus($"保存设置失败: {ex.Message}");
            }
        }

        private void LoadLastUsedSettings()
        {
            if (!File.Exists(SettingsFilePath))
            {
                UpdateStatus("未找到保存的设置，使用默认值");
                // Ensure critical parameters have default values
                if (string.IsNullOrEmpty(txtAuthGateway.Text))
                    txtAuthGateway.Text = "10.10.102.50:801";
                if (string.IsNullOrEmpty(txtLoginMethod.Text))
                    txtLoginMethod.Text = "1";
                if (string.IsNullOrEmpty(txtLogoutAccount.Text))
                    txtLogoutAccount.Text = "drcom";
                if (string.IsNullOrEmpty(txtLogoutPassword.Text))
                    txtLogoutPassword.Text = "123";
                return;
            }

            try
            {
                var settings = JsonSerializer.Deserialize<AppSettings>(File.ReadAllText(SettingsFilePath));
                if (settings == null) return;

                // Account parameters
                txtAccount.Text = settings.LastAccount;
                txtPassword.Password = settings.LastPassword;
                txtCallback.Text = settings.LastCallback ?? "dr1003";
                txtLoginMethod.Text = settings.LastLoginMethod ?? "1";

                // IP parameters
                txtWlanUserIp.Text = settings.LastWlanUserIp;
                txtWlanUserIpv6.Text = settings.LastWlanUserIpv6;
                txtWlanUserMac.Text = settings.LastWlanUserMac;
                txtWlanAcIp.Text = settings.LastWlanAcIp;
                txtAuthGateway.Text = settings.LastAuthGateway ?? "10.10.102.50:801";
                txtTerminalType.Text = settings.LastTerminalType ?? "1";
                txtWlanVlanId.Text = settings.LastWlanVlanId ?? "0";
                txtJsVersion.Text = settings.LastJsVersion ?? "4.1.3";
                txtV.Text = settings.LastV ?? "1157";

                // Multi-group IP settings
                txtWlanUserIp2.Text = settings.LastWlanUserIp2;
                txtWlanUserIpv6_2.Text = settings.LastWlanUserIpv6_2;
                chkAutoAuth.IsChecked = settings.AutoAuthEnabled;

                // Logout parameters
                txtLogoutAccount.Text = settings.LastLogoutAccount ?? "drcom";
                txtLogoutPassword.Text = settings.LastLogoutPassword ?? "123";
                txtAcLogout.Text = settings.LastAcLogout ?? "1";

                // Settings options
                cmbOperator.SelectedIndex = settings.LastOperatorIndex >= 0 ?
                    Math.Min(settings.LastOperatorIndex, cmbOperator.Items.Count - 1) : 0;

                chkSavePassword.IsChecked = settings.LastSavePassword;

                // Timing and startup settings
                txtOnlineInterval.Text = settings.OnlineInterval > 0 ?
                    settings.OnlineInterval.ToString() : "30";

                txtOfflineInterval.Text = settings.OfflineInterval > 0 ?
                    settings.OfflineInterval.ToString() : "5";

                chkAutoStart.IsChecked = settings.AutoStartEnabled;

                cmbTerminalType.SelectedIndex = settings.TerminalTypeIndex >= 0 ?
                    Math.Min(settings.TerminalTypeIndex, cmbTerminalType.Items.Count - 1) : 0;

                // New configuration settings
                chkShowIPv6.IsChecked = settings.ShowIPv6;
                chkShowTerminalType.IsChecked = settings.ShowTerminalType;
                chkDistinguishGroups.IsChecked = settings.DistinguishGroups;

                // Group-specific operator settings
                cmbGroup1Operator.SelectedIndex = settings.Group1OperatorIndex >= 0 ?
                    Math.Min(settings.Group1OperatorIndex, cmbGroup1Operator.Items.Count - 1) : 0;

                cmbGroup1TerminalType.SelectedIndex = settings.Group1TerminalTypeIndex >= 0 ?
                    Math.Min(settings.Group1TerminalTypeIndex, cmbGroup1TerminalType.Items.Count - 1) : 0;

                cmbGroup2Operator.SelectedIndex = settings.Group2OperatorIndex >= 0 ?
                    Math.Min(settings.Group2OperatorIndex, cmbGroup2Operator.Items.Count - 1) : 0;

                cmbGroup2TerminalType.SelectedIndex = settings.Group2TerminalTypeIndex >= 0 ?
                    Math.Min(settings.Group2TerminalTypeIndex, cmbGroup2TerminalType.Items.Count - 1) : 0;


                chkAutoHideOnStart.IsChecked = settings.AutoHideOnStartEnabled;


                // Handle IP group 2 visibility
                if (!string.IsNullOrEmpty(settings.LastWlanUserIp2) || !string.IsNullOrEmpty(settings.LastWlanUserIpv6_2))
                {
                    ipGroup2Added = true;
                    txtWlanUserIp2.Visibility = Visibility.Visible;
                    sepIPGroupDivider.Visibility = Visibility.Visible;
                    txtGroup2Status.Visibility = Visibility.Visible;
                    ((Run)lnkAddIPGroup.Inlines.FirstInline).Text = "-";
                    UpdateGroupStatus(2, "未开始");
                }

                // Handle auto authentication
                if (settings.AutoAuthEnabled && !isAutoAuthRequested)
                {
                    isAutoAuthRequested = true;
                    Dispatcher.BeginInvoke((Action)(async () =>
                    {
                        if (!ValidateAuthParams()) return;
                        if (!ConfirmIpMismatch()) return;
                        SaveLastUsedSettings();
                        ToggleAuthTimer(true);
                        await SendAuthRequest();

                        // 新增：自动认证启动后同步托盘状态
                        UpdateTrayAuthMenuText();
                        UpdateTrayIcon();

                    }), DispatcherPriority.ApplicationIdle);
                }
                if (settings.AutoHideOnStartEnabled)
                {
                    Dispatcher.BeginInvoke((Action)(() =>
                    {
                        Hide(); // 隐藏主窗口
                        TrayIcon.Visibility = Visibility.Visible; // 确保托盘图标显示
                        UpdateStatus("程序已按配置自动隐藏，仅托盘运行");
                    }), DispatcherPriority.ApplicationIdle);
                }
                UpdateStatus("加载上次保存的参数设置");
            }
            catch (Exception ex)
            {
                UpdateStatus($"加载设置失败: {ex.Message}");
            }
        }

        public class AppSettings
        {
            public string LastAccount { get; set; } = "";
            public string LastPassword { get; set; } = "";
            public string LastCallback { get; set; } = "dr1003";
            public string LastLoginMethod { get; set; } = "1";
            public string LastWlanUserIp { get; set; } = "";
            public string LastWlanUserIpv6 { get; set; } = "";
            public string LastWlanUserMac { get; set; } = "";
            public string LastWlanAcIp { get; set; } = "";
            public string LastAuthGateway { get; set; } = "10.10.102.50:801";
            public string LastTerminalType { get; set; } = "1";
            public string LastWlanVlanId { get; set; } = "0";
            public string LastLogoutAccount { get; set; } = "drcom";
            public string LastLogoutPassword { get; set; } = "123";
            public string LastAcLogout { get; set; } = "1";
            public string LastJsVersion { get; set; } = "4.1.3";
            public string LastV { get; set; } = "1157";
            public int LastOperatorIndex { get; set; } = 0;
            public bool LastSavePassword { get; set; } = false;
            public int OnlineInterval { get; set; } = 30;
            public int OfflineInterval { get; set; } = 5;
            public bool AutoStartEnabled { get; set; } = false;
            public int TerminalTypeIndex { get; set; } = 0;
            public string LastWlanUserIp2 { get; set; } = "";
            public string LastWlanUserIpv6_2 { get; set; } = "";
            public bool AutoAuthEnabled { get; set; } = false;

            // New settings
            public bool ShowIPv6 { get; set; } = false;
            public bool ShowTerminalType { get; set; } = true;
            public bool DistinguishGroups { get; set; } = false;
            public int Group1OperatorIndex { get; set; } = 0;
            public int Group1TerminalTypeIndex { get; set; } = 0;
            public int Group2OperatorIndex { get; set; } = 0;
            public int Group2TerminalTypeIndex { get; set; } = 0;

            public bool AutoHideOnStartEnabled { get; set; } = false;
        }
        #endregion

        #region HTTP Request Handling
        private async Task SendAuthRequest(bool isLogout = false)
        {
            try
            {
                // 第一组始终启用
                await SendGroupAuthRequest(1, isLogout);

                // 第二组仅在添加时启用
                if (ipGroup2Added)
                {
                    await SendGroupAuthRequest(2, isLogout);
                }
            }
            catch (Exception ex)
            {
                UpdateStatus($"⚠️ 处理请求时出错: {ex.Message}");
            }
        }

        private async Task SendGroupAuthRequest(int groupIndex, bool isLogout)
        {
            // Save original values
            var originalIp = txtWlanUserIp.Text;
            var originalIpv6 = txtWlanUserIpv6.Text;
            var originalTerminalType = cmbTerminalType.SelectedIndex;
            var originalOperator = cmbOperator.SelectedIndex;

            try
            {
                // Use group-specific values
                if (groupIndex == 2)
                {
                    txtWlanUserIp.Text = txtWlanUserIp2.Text;
                    txtWlanUserIpv6.Text = txtWlanUserIpv6_2.Text;

                    // Use group-specific settings if configured
                    if (chkDistinguishGroups.IsChecked == true)
                    {
                        cmbTerminalType.SelectedIndex = cmbGroup2TerminalType.SelectedIndex;
                        cmbOperator.SelectedIndex = cmbGroup2Operator.SelectedIndex;
                    }
                }
                else if (chkDistinguishGroups.IsChecked == true)
                {
                    cmbTerminalType.SelectedIndex = cmbGroup1TerminalType.SelectedIndex;
                    cmbOperator.SelectedIndex = cmbGroup1Operator.SelectedIndex;
                }

                UpdateGroupStatus(groupIndex, isLogout ? "正在注销..." : "正在认证...");

                var parameters = CreateRequestParameters(isLogout);
                var response = await SendHttpRequest(parameters, isLogout);

                if (response is null)
                {
                    UpdateGroupStatus(groupIndex, "❌ 网络错误，请检查连接");
                    return;
                }

                var statusMessage = ParseResponse(response.Content.ReadAsStringAsync().Result, isLogout);
                UpdateGroupStatus(groupIndex, statusMessage);

                if (!isLogout && !statusMessage.StartsWith("✅"))
                {
                    if (!int.TryParse(txtOfflineInterval.Text, out int offlineInterval))
                    {
                        offlineInterval = 5;
                    }
                    authTimer.Interval = TimeSpan.FromSeconds(Math.Min(offlineInterval, 10));
                }
            }
            finally
            {
                // Restore original values
                txtWlanUserIp.Text = originalIp;
                txtWlanUserIpv6.Text = originalIpv6;
                cmbTerminalType.SelectedIndex = originalTerminalType;
                cmbOperator.SelectedIndex = originalOperator;
            }
        }
        #endregion

        #region IP Refresh
        private void btnRefreshIPs_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                var (ipv4, ipv6) = GetPreferredNetworkIPs();
                txtWlanUserIp.Text = ipv4;

                // Only update IPv6 if configured to show
                if (chkShowIPv6.IsChecked == true)
                {
                    txtWlanUserIpv6.Text = ipv6;
                }

                UpdateStatus($"刷新IP地址完成: IPv4={ipv4}, IPv6={ipv6}");
            }
            catch (Exception ex)
            {
                UpdateStatus($"刷新IP地址错误: {ex.Message}");
            }
        }
        #endregion

        #region Request Creation
        private Dictionary<string, string> CreateRequestParameters(bool isLogout)
        {
            if (isLogout)
            {
                return new Dictionary<string, string>
                {
                    ["callback"] = "dr1004",
                    ["login_method"] = txtLoginMethod.Text,
                    ["user_account"] = txtLogoutAccount.Text,
                    ["user_password"] = txtLogoutPassword.Text,
                    ["ac_logout"] = txtAcLogout.Text,
                    ["register_mode"] = "1",
                    ["wlan_user_ip"] = txtWlanUserIp.Text,
                    ["wlan_user_ipv6"] = chkShowIPv6.IsChecked == true ? txtWlanUserIpv6.Text : "",
                    ["wlan_vlan_id"] = txtWlanVlanId.Text,
                    ["wlan_user_mac"] = txtWlanUserMac.Text,
                    ["wlan_ac_ip"] = txtWlanAcIp.Text,
                    ["wlan_ac_name"] = "",
                    ["jsVersion"] = txtJsVersion.Text,
                    ["v"] = new Random().Next(1000, 9999).ToString(),
                    ["lang"] = "zh-cn"
                };
            }

            // Handle login method
            var loginMethod = string.IsNullOrWhiteSpace(txtLoginMethod.Text)
                ? "1"
                : txtLoginMethod.Text;

            // Get terminal type (0 for PC, 1 for Mobile)
            int terminalCode = chkShowTerminalType.IsChecked == true ?
                cmbTerminalType.SelectedIndex : 1; // Default to mobile if hidden

            // Handle campus network format
            string userAccount;
            var selectedOperator = cmbOperator.SelectedIndex;
            if (selectedOperator == 3) // Campus network
            {
                userAccount = Uri.EscapeDataString($",{terminalCode},{txtAccount.Text}");
            }
            else
            {
                string operatorCode = selectedOperator switch
                {
                    0 => "unicom",
                    1 => "telecom",
                    2 => "cmcc",
                    _ => "unicom"
                };
                userAccount = Uri.EscapeDataString($",{terminalCode},{txtAccount.Text}@{operatorCode}");
            }

            return new Dictionary<string, string>
            {
                ["callback"] = txtCallback.Text,
                ["login_method"] = loginMethod,
                ["user_account"] = userAccount,
                ["user_password"] = Uri.EscapeDataString(txtPassword.Password),
                ["wlan_user_ip"] = txtWlanUserIp.Text,
                ["wlan_user_ipv6"] = chkShowIPv6.IsChecked == true ? txtWlanUserIpv6.Text : "",
                ["wlan_user_mac"] = txtWlanUserMac.Text,
                ["wlan_ac_ip"] = txtWlanAcIp.Text,
                ["wlan_ac_name"] = "",
                ["wlan_vlan_id"] = txtWlanVlanId.Text,
                ["terminal_type"] = txtTerminalType.Text,
                ["jsVersion"] = txtJsVersion.Text,
                ["lang"] = "zh-cn",
                ["v"] = txtV.Text
            };
        }

        private async Task<HttpResponseMessage> SendHttpRequest(
            Dictionary<string, string> parameters, bool isLogout)
        {
            var endpoint = isLogout ? "logout" : "login";
            var authGateway = string.IsNullOrWhiteSpace(txtAuthGateway.Text)
                ? "10.10.102.50:801"
                : txtAuthGateway.Text;

            var baseUrl = $"http://{authGateway}/eportal/portal";
            var displayParams = CreateDisplayParameters(parameters);
            var displayQuery = BuildQueryString(displayParams);
            var displayUrl = $"{baseUrl}/{endpoint}?{displayQuery}";

            UpdateStatus($"正在发送{(isLogout ? "注销" : "认证")}请求: {displayUrl}");

            try
            {
                using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(20));
                return await client.GetAsync(
                    $"{baseUrl}/{endpoint}?{BuildQueryString(parameters)}",
                    cts.Token
                );
            }
            catch (TaskCanceledException)
            {
                UpdateStatus($"❌ 连接服务器超时，已取消本次 {(isLogout ? "注销" : "认证")}操作");
                return null;
            }
            catch (HttpRequestException ex)
            {
                UpdateStatus($"❌ 网络连接错误: {ex.Message}");
                return null;
            }
            catch (SocketException ex)
            {
                UpdateStatus($"❌ 网络套接字错误: {ex.SocketErrorCode}");
                return null;
            }
            catch (Exception ex)
            {
                UpdateStatus($"❌ 未知请求错误: {ex.Message}");
                return null;
            }
        }

        private Dictionary<string, string> CreateDisplayParameters(Dictionary<string, string> parameters)
        {
            return parameters.ToDictionary(
                p => p.Key,
                p => p.Key.Contains("password", StringComparison.OrdinalIgnoreCase)
                    ? "******"
                    : p.Value
            );
        }

        private string ParseResponse(string content, bool isLogout)
        {
            if (isLogout)
            {
                return content.Contains("成功") ? "✅ 注销成功" : $"❌ 注销失败: {content}";
            }

            return content.Contains("认证成功") ? "✅ 认证成功" :
                   content.Contains("已经在线") ? "✅ 当前IP在线" :
                   content.Contains("账号不存在") ? "❌ 认证失败：账号不存在" :
                   content.Contains("密码错误") ? "❌ 认证失败：密码错误" :
                   content.Contains("尚未提供支持") ? "❌ 认证方式不被支持" :
                   content.Contains("Max") || content.Contains("online count") ? "❌ 设备数量过多" :
                   content.Contains("认证失败") ? "❌ 认证失败" :
                   $" {content}";
        }

        private string BuildQueryString(Dictionary<string, string> parameters)
        {
            return string.Join("&", parameters
                .Where(p => !string.IsNullOrEmpty(p.Value))
                .Select(p => $"{p.Key}={p.Value}"));
        }
        #endregion

        #region Event Handlers
        // 原有代码...

        /// <summary>
        /// 托盘菜单的认证开关点击事件（等效主界面btnLogin）
        /// </summary>
        private async void ToggleAuthMenu_Click(object sender, RoutedEventArgs e)
        {
            // 1. 隐藏托盘菜单（点击后自动关闭）
            var contextMenu = (ContextMenu)((MenuItem)sender).Parent;
            contextMenu.IsOpen = false;

            // 2. 同主界面按钮逻辑：先验证参数
            if (!ValidateAuthParams()) return;

            // 3. 检查IP是否匹配（不匹配则提示确认）
            if (!ConfirmIpMismatch()) return;

            // 4. 切换认证状态（启动/停止定时器）
            if (authTimer.IsEnabled)
            {
                ToggleAuthTimer(false); // 停止认证
            }
            else
            {
                SaveLastUsedSettings(); // 保存设置
                ToggleAuthTimer(true);  // 启动认证
                await SendAuthRequest(); // 立即发送一次认证请求
            }

            // 5. 同步更新托盘菜单文本和图标
            UpdateTrayAuthMenuText();
            UpdateTrayIcon();
        }
        private void ParseUrl_Click(object sender, RoutedEventArgs e)
        {
            if (string.IsNullOrWhiteSpace(txtFullUrl.Text))
            {
                UpdateStatus("URL不能为空");
                return;
            }

            try
            {
                var uri = new Uri(txtFullUrl.Text);
                var query = HttpUtility.ParseQueryString(uri.Query);
                var path = uri.AbsolutePath.ToLower();

                // Detect URL type (login/logout)
                bool isLogoutUrl = path.Contains("logout", StringComparison.OrdinalIgnoreCase);

                // Authentication gateway
                txtAuthGateway.Text = uri.Authority;

                // Common parameters
                txtLoginMethod.Text = query["login_method"] ?? txtLoginMethod.Text;
                txtCallback.Text = query["callback"] ?? txtCallback.Text;
                txtWlanUserIp.Text = query["wlan_user_ip"] ?? txtWlanUserIp.Text;
                txtWlanUserIpv6.Text = query["wlan_user_ipv6"] ?? txtWlanUserIpv6.Text;
                txtWlanUserMac.Text = query["wlan_user_mac"] ?? txtWlanUserMac.Text;
                txtWlanAcIp.Text = query["wlan_ac_ip"] ?? txtWlanAcIp.Text;
                txtJsVersion.Text = query["jsVersion"] ?? txtJsVersion.Text;
                txtV.Text = query["v"] ?? txtV.Text;
                txtWlanVlanId.Text = query["wlan_vlan_id"] ?? txtWlanVlanId.Text;
                txtTerminalType.Text = query["terminal_type"] ?? txtTerminalType.Text;

                // Special account handling
                if (isLogoutUrl)
                {
                    txtLogoutAccount.Text = query["user_account"] ?? txtLogoutAccount.Text;
                    txtLogoutPassword.Text = query["user_password"] ?? txtLogoutPassword.Text;
                    txtAcLogout.Text = query["ac_logout"] ?? txtAcLogout.Text;
                }
                else
                {
                    ParseAccountAndOperator(query["user_account"]);
                    SetPasswordIfValid(query["user_password"]);
                }

                txtFullUrl.Text = "";
                UpdateStatus($"已解析{(isLogoutUrl ? "注销" : "登录")}URL参数");
            }
            catch (Exception ex)
            {
                UpdateStatus($"解析失败: {ex.Message}");
            }
        }

        private void ParseAccountAndOperator(string accountValue)
        {
            if (string.IsNullOrEmpty(accountValue)) return;

            var decodedAccount = HttpUtility.UrlDecode(accountValue);
            if (!string.IsNullOrEmpty(decodedAccount))
            {
                // Parse campus network format
                if (!decodedAccount.Contains('@'))
                {
                    var parts = decodedAccount.Split(',');
                    if (parts.Length > 2)
                    {
                        txtAccount.Text = parts[2];
                        cmbOperator.SelectedIndex = 3; // Campus network
                        if (int.TryParse(parts[1], out int terminalIndex))
                            cmbTerminalType.SelectedIndex = terminalIndex == 1 ? 1 : 0;
                    }
                }
                else
                {
                    var accountParts = decodedAccount.Split('@');
                    if (accountParts.Length > 1)
                    {
                        var prefixParts = accountParts[0].Split(',');
                        if (prefixParts.Length > 2)
                        {
                            txtAccount.Text = prefixParts[2];
                            if (int.TryParse(prefixParts[1], out int terminalIndex))
                                cmbTerminalType.SelectedIndex = terminalIndex == 1 ? 1 : 0;
                        }

                        cmbOperator.SelectedIndex = accountParts[1].ToLower() switch
                        {
                            "unicom" => 0,
                            "telecom" => 1,
                            "cmcc" => 2,
                            _ => 0
                        };
                    }
                }
            }
        }

        private void SetPasswordIfValid(string passwordValue)
        {
            if (!string.IsNullOrEmpty(passwordValue))
            {
                txtPassword.Password = HttpUtility.UrlDecode(passwordValue);
            }
        }

        private async void btnLogin_Click(object sender, RoutedEventArgs e)
        {
            if (!ValidateAuthParams()) return;

            if (authTimer.IsEnabled)
            {
                ToggleAuthTimer(false);
                return;
            }

            if (!ConfirmIpMismatch()) return;

            SaveLastUsedSettings();
            ToggleAuthTimer(true);
            await SendAuthRequest();
        }

        private bool ValidateAuthParams()
        {
            if (string.IsNullOrEmpty(txtAccount.Text))
            {
                MessageBox.Show("账号不能为空", "输入错误", MessageBoxButton.OK, MessageBoxImage.Warning);
                return false;
            }

            if (string.IsNullOrEmpty(txtPassword.Password))
            {
                UpdateStatus("密码不能为空");
                return false;
            }

            if (string.IsNullOrWhiteSpace(txtLoginMethod.Text))
            {
                txtLoginMethod.Text = "1";
            }

            return true;
        }

        private bool ConfirmIpMismatch()
        {
            if (IsCurrentActiveIP(txtWlanUserIp.Text) &&
                (string.IsNullOrEmpty(txtWlanUserIpv6.Text) ||
                 IsCurrentActiveIP(txtWlanUserIpv6.Text)))
                return true;

            var result = MessageBox.Show(
                "您填写的IP或IPv6地址不是本机地址，继续认证可能导致被奇怪的ip占用位置。是否继续？",
                "注意",
                MessageBoxButton.OKCancel,
                MessageBoxImage.Warning
            );

            return result == MessageBoxResult.OK;
        }

        private async void LogoutLink_Click(object sender, RoutedEventArgs e)
        {
            await SendAuthRequest(isLogout: true);
        }
        #endregion

        #region Status Management
        private void UpdateGroupStatus(int groupIndex, string status)
        {
            string groupPrefix = $"【IP组{groupIndex}】 ";
            string statusWithGroup = groupPrefix + status;

            Dispatcher.Invoke(() =>
            {
                if (groupIndex == 1)
                {
                    group1LatestStatus = status;
                    txtGroup1Status.Text = $"IP 组 1：{status}";
                }
                else if (groupIndex == 2 && ipGroup2Added)
                {
                    group2LatestStatus = status;
                    txtGroup2Status.Text = $"IP 组 2：{status}";
                    txtGroup2Status.Visibility = Visibility.Visible;
                }

                UpdateStatus(statusWithGroup);
                UpdateTrayIcon(); // 更新托盘图标
            });
        }

        private void UpdateStatus(string message)
        {
            Dispatcher.Invoke(() =>
            {
                var lines = txtStatus.Text.Split('\n').ToList();

                if (lines.Count > MaxLogLines)
                {
                    lines.RemoveRange(MaxLogLines, lines.Count - MaxLogLines);
                    txtStatus.Text = string.Join("\n", lines);
                }

                txtStatus.Text = $"[{DateTime.Now:T}] {message}\n{txtStatus.Text}";
            });
        }
        #endregion

        #region Helper Methods
        // 原有代码...

        /// <summary>
        /// 更新托盘菜单的认证开关文本（开始/停止维持认证）
        /// </summary>
        private void UpdateTrayAuthMenuText()
        {
            Dispatcher.Invoke(() =>
            {
                // 根据定时器状态判断认证状态：定时器运行=正在维持认证
                ToggleAuthMenu.Header = authTimer.IsEnabled
                    ? "停止维持认证"
                    : "开始维持认证";
            });
        }

        /// <summary>
        /// 更新托盘图标（根据认证状态切换）
        /// </summary>
        /// <summary>
        /// 更新托盘图标（根据认证状态切换）
        /// 逻辑：
        /// - 若认证状态不是“当前IP在线”或“认证成功”，用gateway3.ico
        /// - 否则按原逻辑：认证中用gateway2.ico，未认证用gateway1.ico
        /// </summary>
        private void UpdateTrayIcon()
        {
            Dispatcher.Invoke(() =>
            {
                // 1. 判断当前认证状态是否为成功或在线或正在认证
                bool isSuccessOrOnline = false;

                // 检查第一组状态（始终）
                if (group1LatestStatus.StartsWith("✅ 认证成功") || group1LatestStatus.StartsWith("✅ 当前IP在线") || group1LatestStatus.StartsWith("正在认证"))
                {
                    isSuccessOrOnline = true;
                }
                // 检查第二组状态（仅当启用时）
                else if (ipGroup2Added &&
                        (group2LatestStatus.StartsWith("✅ 认证成功") || group2LatestStatus.StartsWith("✅ 当前IP在线") || group1LatestStatus.StartsWith("正在认证")))
                {
                    isSuccessOrOnline = true;
                }

                // 2. 根据状态选择图标
                string iconPath = isSuccessOrOnline
                    ? (authTimer.IsEnabled ? "pack://application:,,,/res/gateway2.ico" : "pack://application:,,,/res/gateway1.ico")
                    : "pack://application:,,,/res/gateway3.ico"; // 状态异常时用gateway3

                TrayIcon.IconSource = new BitmapImage(new Uri(iconPath));
            });
        }


        private string GetOperatorCode()
        {
            return cmbOperator.SelectedIndex switch
            {
                0 => "unicom",
                1 => "telecom",
                2 => "cmcc",
                3 => "",
                _ => "unicom"
            };
        }

        protected override void OnClosed(EventArgs e)
        {
            authTimer?.Stop();
            base.OnClosed(e);
        }

        private void CheckAutoStartSetting()
        {
            try
            {
                using (RegistryKey key = Registry.CurrentUser.OpenSubKey(@"Software\Microsoft\Windows\CurrentVersion\Run", true))
                {
                    if (key == null) return;

                    // 自动获取程序集名称作为appName
                    string appName = Assembly.GetExecutingAssembly().GetName().Name;
                    // 获取当前进程的主exe路径
                    string appPath = Process.GetCurrentProcess().MainModule.FileName;

                    chkAutoStart.IsChecked = key.GetValue(appName)?.ToString() == appPath;
                }
            }
            catch (Exception ex)
            {
                UpdateStatus($"检查自启动设置时出错: {ex.Message}");
            }
        }

        // 修改chkAutoStart_Click方法
        private void chkAutoStart_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                // 自动获取程序集名称作为appName
                string appName = Assembly.GetExecutingAssembly().GetName().Name;
                // 获取当前进程的主exe路径
                string appPath = Process.GetCurrentProcess().MainModule.FileName;

                using (RegistryKey key = Registry.CurrentUser.OpenSubKey(@"Software\Microsoft\Windows\CurrentVersion\Run", true))
                {
                    if (chkAutoStart.IsChecked == true)
                    {
                        key.SetValue(appName, appPath);
                        UpdateStatus($"已设置为开机自启动 (名称: {appName})");
                    }
                    else
                    {
                        key.DeleteValue(appName, false);
                        UpdateStatus($"已取消开机自启动 (名称: {appName})");
                    }
                }
            }
            catch (Exception ex)
            {
                UpdateStatus($"修改自启动设置出错: {ex.Message}");
            }
        }

        #endregion
        #region Task Bar
        protected override void OnClosing(System.ComponentModel.CancelEventArgs e)
        {
            e.Cancel = true;
            WindowState = WindowState.Minimized;
        }
        private void Window_StateChanged(object sender, System.EventArgs e)
        {
            if (WindowState == WindowState.Minimized)
            {
                Hide();
                TrayIcon.Visibility = Visibility.Visible;
            }
        }
        private void TrayIcon_TrayLeftMouseDown(object sender, RoutedEventArgs e)
        {
            // 判断窗口当前是否可见
            if (IsVisible)
            {
                // 窗口可见时，隐藏窗口（仅保留托盘）
                Hide();
                UpdateStatus("窗口已隐藏，托盘继续运行");
            }
            else
            {
                // 窗口隐藏时，显示窗口
                ShowMainWindow();
            }
        }

        private void ShowMainWindow()
        {
            Show();
            WindowState = WindowState.Normal;
            Activate();
            
        }
        private void ShowWindow_Click(object sender, RoutedEventArgs e)
        {
            ShowMainWindow();
        }

        private void ExitApp_Click(object sender, RoutedEventArgs e)
        {
            TrayIcon.Dispose();
            Application.Current.Shutdown();
        }


        #endregion
    }
}