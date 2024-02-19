@{
    GUID = 'A51E6D9E-BC14-41A7-98A8-888195641250'
    Author="Microsoft Corporation"
    CompanyName="Microsoft Corporation"
    Copyright="Copyright (C) Microsoft Corporation. All rights reserved."
    ModuleVersion = '1.0'
    NestedModules = @('MSFT_MpPerformanceRecording.psm1')

    FormatsToProcess = @('MSFT_MpPerformanceReport.Format.ps1xml')

    CompatiblePSEditions = @('Desktop', 'Core')

    FunctionsToExport = @( 'New-MpPerformanceRecording',
                           'Get-MpPerformanceReport'
                           )
    HelpInfoUri="https://aka.ms/winsvr-2022-pshelp"
    PowerShellVersion = '5.1'
}

# SIG # Begin signature block
# MIIlfAYJKoZIhvcNAQcCoIIlbTCCJWkCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCALMtnQG5KhaVi8
# /j7ONkfb/EMugE0iBrx7n8hqD9uLdaCCC2IwggTvMIID16ADAgECAhMzAAAKc/FU
# CYZWEHhHAAAAAApzMA0GCSqGSIb3DQEBCwUAMHkxCzAJBgNVBAYTAlVTMRMwEQYD
# VQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNy
# b3NvZnQgQ29ycG9yYXRpb24xIzAhBgNVBAMTGk1pY3Jvc29mdCBXaW5kb3dzIFBD
# QSAyMDEwMB4XDTIzMDIxNjE5MDA0NFoXDTI0MDEzMTE5MDA0NFowcDELMAkGA1UE
# BhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAc
# BgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEaMBgGA1UEAxMRTWljcm9zb2Z0
# IFdpbmRvd3MwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQC0znTAytEY
# jN+IOBOLzQZ+M2rbqzlt9u2/9snBb9X4YHf6QwG+ccLIj8wyn0+lHLagkHw2kQ9h
# nymXhJLv+fVpMlEyNigGyAmH0rM1crsQoUToGaq2Um28OhUm9CRxqGGl6rvmZ1Q4
# 5ExvAq6/gE0JUkmJyPpRHZuJIdmceH0DE0ACeCj9jthtdrtNsDCGQcjvqZh0sSXi
# uwxX/pgvc8mHEJIfqhK95dTu0CVz7qkhOCM1ePU8gOWbC17NAptqGeps0v5efEEy
# rYvzxee52fUO7R2it8JtXDuJ1r9X7TDLBPlSj4ZejWMS9ZelvGSrv98UyJzainia
# Q81xAGxR++BdAgMBAAGjggF3MIIBczAfBgNVHSUEGDAWBgorBgEEAYI3CgMGBggr
# BgEFBQcDAzAdBgNVHQ4EFgQUrUcDAOl/pmci0aNJQcKExaMhzmQwVAYDVR0RBE0w
# S6RJMEcxLTArBgNVBAsTJE1pY3Jvc29mdCBJcmVsYW5kIE9wZXJhdGlvbnMgTGlt
# aXRlZDEWMBQGA1UEBRMNMjMwMDI4KzUwMDE5MTAfBgNVHSMEGDAWgBTRT6mKBwjO
# 9CQYmOUA//PWeR03vDBTBgNVHR8ETDBKMEigRqBEhkJodHRwOi8vY3JsLm1pY3Jv
# c29mdC5jb20vcGtpL2NybC9wcm9kdWN0cy9NaWNXaW5QQ0FfMjAxMC0wNy0wNi5j
# cmwwVwYIKwYBBQUHAQEESzBJMEcGCCsGAQUFBzAChjtodHRwOi8vd3d3Lm1pY3Jv
# c29mdC5jb20vcGtpL2NlcnRzL01pY1dpblBDQV8yMDEwLTA3LTA2LmNydDAMBgNV
# HRMBAf8EAjAAMA0GCSqGSIb3DQEBCwUAA4IBAQA/Xky5Ry4E9i8YZgEukoocB2Sh
# aEZEhCUE3WnXfaylCZVPoc/6VsOAF4aLBk4/mxAq7HUjYZPhBMZ1c8bsCBBnj3aK
# YiFLzX9SzfwnTqH7giRpBGfaiU1P+I8R6LtUb07hO1KDIJY4T//2wzvqze8l3nn+
# jh9O5tWA+832F/jj9VObTTGx5eBKcDQmF/U7EgWSVWGDeHFRpJMpcQJTLAMwkbMR
# vijbfdR7A+48ENPN+Sjfln0AW2Zb+i4FP0chgRtdY4szEybOAZAVpF4Wp/49h/Wz
# Pd5EK/OqdKwr7Z1/EeKzvR4RgdkUsodwym3KnoEC/SbhO/Va/T5fh3araOJ+MIIG
# azCCBFOgAwIBAgIKYQxqGQAAAAAABDANBgkqhkiG9w0BAQsFADCBiDELMAkGA1UE
# BhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAc
# BgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEyMDAGA1UEAxMpTWljcm9zb2Z0
# IFJvb3QgQ2VydGlmaWNhdGUgQXV0aG9yaXR5IDIwMTAwHhcNMTAwNzA2MjA0MDIz
# WhcNMjUwNzA2MjA1MDIzWjB5MQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGlu
# Z3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBv
# cmF0aW9uMSMwIQYDVQQDExpNaWNyb3NvZnQgV2luZG93cyBQQ0EgMjAxMDCCASIw
# DQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAMB5uzqx8A+EuK1kKnUWc9C7B/Y+
# DZ0U5LGfwciUsDh8H9AzVfW6I2b1LihIU8cWg7r1Uax+rOAmfw90/FmV3MnGovdS
# cFosHZSrGb+vlX2vZqFvm2JubUu8LzVs3qRqY1pf+/MNTWHMCn4x62wK0E2XD/1/
# OEbmisdzaXZVaZZM5NjwNOu6sR/OKX7ET50TFasTG3JYYlZsioGjZHeYRmUpnYMU
# pUwIoIPXIx/zX99vLM/aFtgOcgQo2Gs++BOxfKIXeU9+3DrknXAna7/b/B7HB9jA
# vguTHijgc23SVOkoTL9rXZ//XTMSN5UlYTRqQst8nTq7iFnho0JtOlBbSNECAwEA
# AaOCAeMwggHfMBAGCSsGAQQBgjcVAQQDAgEAMB0GA1UdDgQWBBTRT6mKBwjO9CQY
# mOUA//PWeR03vDAZBgkrBgEEAYI3FAIEDB4KAFMAdQBiAEMAQTALBgNVHQ8EBAMC
# AYYwDwYDVR0TAQH/BAUwAwEB/zAfBgNVHSMEGDAWgBTV9lbLj+iiXGJo0T2UkFvX
# zpoYxDBWBgNVHR8ETzBNMEugSaBHhkVodHRwOi8vY3JsLm1pY3Jvc29mdC5jb20v
# cGtpL2NybC9wcm9kdWN0cy9NaWNSb29DZXJBdXRfMjAxMC0wNi0yMy5jcmwwWgYI
# KwYBBQUHAQEETjBMMEoGCCsGAQUFBzAChj5odHRwOi8vd3d3Lm1pY3Jvc29mdC5j
# b20vcGtpL2NlcnRzL01pY1Jvb0NlckF1dF8yMDEwLTA2LTIzLmNydDCBnQYDVR0g
# BIGVMIGSMIGPBgkrBgEEAYI3LgMwgYEwPQYIKwYBBQUHAgEWMWh0dHA6Ly93d3cu
# bWljcm9zb2Z0LmNvbS9QS0kvZG9jcy9DUFMvZGVmYXVsdC5odG0wQAYIKwYBBQUH
# AgIwNB4yIB0ATABlAGcAYQBsAF8AUABvAGwAaQBjAHkAXwBTAHQAYQB0AGUAbQBl
# AG4AdAAuIB0wDQYJKoZIhvcNAQELBQADggIBAC5Bpoa1Bm/wgIX6O8oX6cn65DnC
# lHDDZJTD2FamkI7+5Jr0bfVvjlONWqjzrttGbL5/HVRWGzwdccRRFVR+v+6llUIz
# /Q2QJCTj+dyWyvy4rL/0wjlWuLvtc7MX3X6GUCOLViTKu6YdmocvJ4XnobYKnA0b
# jPMAYkG6SHSHgv1QyfSHKcMDqivfGil56BIkmobt0C7TQIH1B18zBlRdQLX3sWL9
# TUj3bkFHUhy7G8JXOqiZVpPUxt4mqGB1hrvsYqbwHQRF3z6nhNFbRCNjJTZ3b65b
# 3CLVFCNqQX/QQqbb7yV7BOPSljdiBq/4Gw+Oszmau4n1NQblpFvDjJ43X1PRozf9
# pE/oGw5rduS4j7DC6v119yxBt5yj4R4F/peSy39ZA22oTo1OgBfU1XL2VuRIn6Mj
# ugagwI7RiE+TIPJwX9hrcqMgSfx3DF3Fx+ECDzhCEA7bAq6aNx1QgCkepKfZxpol
# Vf1Ayq1kEOgx+RJUeRryDtjWqx4z/gLnJm1hSY/xJcKLdJnf+ZMakBzu3ZQzDkJQ
# 239Q+J9iguymghZ8ZrzsmbDBWF2osJphFJHRmS9J5D6Bmdbm78rj/T7u7AmGAwcN
# Gw186/RayZXPhxIKXezFApLNBZlyyn3xKhAYOOQxoyi05kzFUqOcasd9wHEJBA1w
# 3gI/h+5WoezrtUyFMYIZcDCCGWwCAQEwgZAweTELMAkGA1UEBhMCVVMxEzARBgNV
# BAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jv
# c29mdCBDb3Jwb3JhdGlvbjEjMCEGA1UEAxMaTWljcm9zb2Z0IFdpbmRvd3MgUENB
# IDIwMTACEzMAAApz8VQJhlYQeEcAAAAACnMwDQYJYIZIAWUDBAIBBQCgga4wGQYJ
# KoZIhvcNAQkDMQwGCisGAQQBgjcCAQQwHAYKKwYBBAGCNwIBCzEOMAwGCisGAQQB
# gjcCARUwLwYJKoZIhvcNAQkEMSIEIBhT7C0VQ9IYyvNiupSGOc577LyiUPub5f/V
# TSflWIz9MEIGCisGAQQBgjcCAQwxNDAyoBSAEgBNAGkAYwByAG8AcwBvAGYAdKEa
# gBhodHRwOi8vd3d3Lm1pY3Jvc29mdC5jb20wDQYJKoZIhvcNAQEBBQAEggEAsTtd
# TCeHf228YI4mUtB3oNWFKPxxRHNXwbWFg2s4sZxofUXpx0AqKHMcEIr0WihNj66l
# fYefW0ErLhOAnar1qXKTUlj8xq3mi2DberU1woTSZcC8/ouqzG6wNQ1TkB18L263
# IuKeiVZG3jD3GJU1QfhH5GmcFdLZyUzpZL46eZsuRh+RkWIoVaCBJyVhuy3/FWTj
# SXDpymmllLK/700LxksXsfkmrw6YGXqIqS8Kp9rsZDsnMXKvBM6zzrk2XXuCKfzf
# Uum3JciHJG9fQ9JoQBAMFLwB0kHCA1lPcWNVV77morhXHjZPAu3DDvioy25E+BAD
# JDzzvXxBWkZm0msNjKGCFv8wghb7BgorBgEEAYI3AwMBMYIW6zCCFucGCSqGSIb3
# DQEHAqCCFtgwghbUAgEDMQ8wDQYJYIZIAWUDBAIBBQAwggFQBgsqhkiG9w0BCRAB
# BKCCAT8EggE7MIIBNwIBAQYKKwYBBAGEWQoDATAxMA0GCWCGSAFlAwQCAQUABCCU
# hY7p18muK9BCJv3Np7XTad9DQYgxMsHD+pWFRnVtVgIGZGzWuZxgGBIyMDIzMDYw
# ODA1MjAxOS42N1owBIACAfSggdCkgc0wgcoxCzAJBgNVBAYTAlVTMRMwEQYDVQQI
# EwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3Nv
# ZnQgQ29ycG9yYXRpb24xJTAjBgNVBAsTHE1pY3Jvc29mdCBBbWVyaWNhIE9wZXJh
# dGlvbnMxJjAkBgNVBAsTHVRoYWxlcyBUU1MgRVNOOjNFN0EtRTM1OS1BMjVEMSUw
# IwYDVQQDExxNaWNyb3NvZnQgVGltZS1TdGFtcCBTZXJ2aWNloIIRVzCCBwwwggT0
# oAMCAQICEzMAAAHJ+tWOJSB0Al4AAQAAAckwDQYJKoZIhvcNAQELBQAwfDELMAkG
# A1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQx
# HjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEmMCQGA1UEAxMdTWljcm9z
# b2Z0IFRpbWUtU3RhbXAgUENBIDIwMTAwHhcNMjIxMTA0MTkwMTM4WhcNMjQwMjAy
# MTkwMTM4WjCByjELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAO
# BgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEl
# MCMGA1UECxMcTWljcm9zb2Z0IEFtZXJpY2EgT3BlcmF0aW9uczEmMCQGA1UECxMd
# VGhhbGVzIFRTUyBFU046M0U3QS1FMzU5LUEyNUQxJTAjBgNVBAMTHE1pY3Jvc29m
# dCBUaW1lLVN0YW1wIFNlcnZpY2UwggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIK
# AoICAQDWcuLljm/Pwr5ajGGTuoZb+8LGLl65MzTVOIRsU4byDtIUHRUyNiCjpOJH
# OA5D4I3nc4E4qXIwdbNEvjG9pLTdmUiB60ggtiIBKiCwS2WPMSVEc7t8MYMVZx3P
# 6UI1iYmjO1sbc8yufFuVQcdSSvgLsQEdvZjTsZ3kYkGA/z7kBk2xOWwcZzMezjma
# Y/utSBwyf/9zxD8ZhKp1Pg5cQunneH30SfIXjNyx3ZkWPF2PWU/xAbBllLgXzYkE
# Z7akKtJqTIWNPHMUpQ7BxB6vAFH9hpCXLua0Ktrg81zIRCb6f8sNx79VWJBrw4za
# cFkcrDoLIyoTMUknLkeLPPxnrGuqosq2Ly+IlRDQW2qRNdJHf//Dw8ArIGW8hhMU
# X8vLcmHdxtV46BKa5s5XC/ycx6FxBvYC3FxT+V3IRSrLz+2EQchY1pvMdfHk70Ph
# u1Lqgl2AuYfGtMG0axxVCrHTPn99QiQsTu1vB+irzhwX9REsTLDernspXZTiA6Fz
# fnpdgRVB0lejpUVYFANhvNqdDbnNjbVQKSPzbULIP3SCqs7etA+VxCjp6vBbYMXZ
# +yaABtWrNCzPpGSZp/Pit7XuSbup7T0+7AfDl7fHlkgYShWV82cm/r7znW7ApfoC
# lkXE/N5Cjtb/kG1pOaRkSHBjkB0I+A+/RpogRCfaoXsy8XAJywIDAQABo4IBNjCC
# ATIwHQYDVR0OBBYEFAVvnWdGwjyhvng6FMV5UXtELjLLMB8GA1UdIwQYMBaAFJ+n
# FV0AXmJdg/Tl0mWnG1M1GelyMF8GA1UdHwRYMFYwVKBSoFCGTmh0dHA6Ly93d3cu
# bWljcm9zb2Z0LmNvbS9wa2lvcHMvY3JsL01pY3Jvc29mdCUyMFRpbWUtU3RhbXAl
# MjBQQ0ElMjAyMDEwKDEpLmNybDBsBggrBgEFBQcBAQRgMF4wXAYIKwYBBQUHMAKG
# UGh0dHA6Ly93d3cubWljcm9zb2Z0LmNvbS9wa2lvcHMvY2VydHMvTWljcm9zb2Z0
# JTIwVGltZS1TdGFtcCUyMFBDQSUyMDIwMTAoMSkuY3J0MAwGA1UdEwEB/wQCMAAw
# EwYDVR0lBAwwCgYIKwYBBQUHAwgwDQYJKoZIhvcNAQELBQADggIBADaoupxm30eK
# QgdyPsCWceGOi7FKM54FpMT4QrxpdxUub1wDwPb9ljY5Sli852G4MRX2ESVWbOim
# Im6T/EFiHp1YlNGGZLuFWOsa2rNIVbQt9+xHKyPGSm6rKEeIEPExcwZnoZ3NR+pU
# /Zl3Y74n8FhAmCz00djP8IzhdpE/5PZUzckTWZI7Wotr6Z8HjbtCIuP8kLtNRiCH
# hFj6gswVW5Alm9diX+MhMV9SmkmgBqQGvRVzavWQ/kOIlo29lYn9y5hqJZDiT3Gn
# DrAbPeqrvEBaeUbOxrDAWGO3CrkQf+zfssJ96HK4LDxlEn1be2BIV6kBUzuxQT4+
# vdS76I+8FXhOxMM0UvQJUg9f7Vc4nphEZgnaQcamgZz/myADYgpByX3tkNgkiqLG
# DAo1+3I3vQ7QBNulNWGxs3TUVWWLQf6+BwaHLOTqOkDLAc8NJD/GgR4ZTj7o8VNc
# xE798zMZxRx/RkepkybRSGgfy062TXyToHvkoldO1jdkzulN+6tK/ZCu/nPMIGLL
# Ky04/D8gkj6T2ilOBq2sLf0vr38rDK0PTHu3SOZNe2Utloa+hKWN3LKvpANFWSqw
# JotRJKwCJZ5q/mqDrhTeYuZ56SjQT1MnnLO03+NyLOUfHReyA643qy5vcI9XsAAw
# yIqil1BiqI9e70jG+pdPsIT9IwLalw3JMIIHcTCCBVmgAwIBAgITMwAAABXF52ue
# AptJmQAAAAAAFTANBgkqhkiG9w0BAQsFADCBiDELMAkGA1UEBhMCVVMxEzARBgNV
# BAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jv
# c29mdCBDb3Jwb3JhdGlvbjEyMDAGA1UEAxMpTWljcm9zb2Z0IFJvb3QgQ2VydGlm
# aWNhdGUgQXV0aG9yaXR5IDIwMTAwHhcNMjEwOTMwMTgyMjI1WhcNMzAwOTMwMTgz
# MjI1WjB8MQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UE
# BxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSYwJAYD
# VQQDEx1NaWNyb3NvZnQgVGltZS1TdGFtcCBQQ0EgMjAxMDCCAiIwDQYJKoZIhvcN
# AQEBBQADggIPADCCAgoCggIBAOThpkzntHIhC3miy9ckeb0O1YLT/e6cBwfSqWxO
# dcjKNVf2AX9sSuDivbk+F2Az/1xPx2b3lVNxWuJ+Slr+uDZnhUYjDLWNE893MsAQ
# GOhgfWpSg0S3po5GawcU88V29YZQ3MFEyHFcUTE3oAo4bo3t1w/YJlN8OWECesSq
# /XJprx2rrPY2vjUmZNqYO7oaezOtgFt+jBAcnVL+tuhiJdxqD89d9P6OU8/W7IVW
# Te/dvI2k45GPsjksUZzpcGkNyjYtcI4xyDUoveO0hyTD4MmPfrVUj9z6BVWYbWg7
# mka97aSueik3rMvrg0XnRm7KMtXAhjBcTyziYrLNueKNiOSWrAFKu75xqRdbZ2De
# +JKRHh09/SDPc31BmkZ1zcRfNN0Sidb9pSB9fvzZnkXftnIv231fgLrbqn427DZM
# 9ituqBJR6L8FA6PRc6ZNN3SUHDSCD/AQ8rdHGO2n6Jl8P0zbr17C89XYcz1DTsEz
# OUyOArxCaC4Q6oRRRuLRvWoYWmEBc8pnol7XKHYC4jMYctenIPDC+hIK12NvDMk2
# ZItboKaDIV1fMHSRlJTYuVD5C4lh8zYGNRiER9vcG9H9stQcxWv2XFJRXRLbJbqv
# UAV6bMURHXLvjflSxIUXk8A8FdsaN8cIFRg/eKtFtvUeh17aj54WcmnGrnu3tz5q
# 4i6tAgMBAAGjggHdMIIB2TASBgkrBgEEAYI3FQEEBQIDAQABMCMGCSsGAQQBgjcV
# AgQWBBQqp1L+ZMSavoKRPEY1Kc8Q/y8E7jAdBgNVHQ4EFgQUn6cVXQBeYl2D9OXS
# ZacbUzUZ6XIwXAYDVR0gBFUwUzBRBgwrBgEEAYI3TIN9AQEwQTA/BggrBgEFBQcC
# ARYzaHR0cDovL3d3dy5taWNyb3NvZnQuY29tL3BraW9wcy9Eb2NzL1JlcG9zaXRv
# cnkuaHRtMBMGA1UdJQQMMAoGCCsGAQUFBwMIMBkGCSsGAQQBgjcUAgQMHgoAUwB1
# AGIAQwBBMAsGA1UdDwQEAwIBhjAPBgNVHRMBAf8EBTADAQH/MB8GA1UdIwQYMBaA
# FNX2VsuP6KJcYmjRPZSQW9fOmhjEMFYGA1UdHwRPME0wS6BJoEeGRWh0dHA6Ly9j
# cmwubWljcm9zb2Z0LmNvbS9wa2kvY3JsL3Byb2R1Y3RzL01pY1Jvb0NlckF1dF8y
# MDEwLTA2LTIzLmNybDBaBggrBgEFBQcBAQROMEwwSgYIKwYBBQUHMAKGPmh0dHA6
# Ly93d3cubWljcm9zb2Z0LmNvbS9wa2kvY2VydHMvTWljUm9vQ2VyQXV0XzIwMTAt
# MDYtMjMuY3J0MA0GCSqGSIb3DQEBCwUAA4ICAQCdVX38Kq3hLB9nATEkW+Geckv8
# qW/qXBS2Pk5HZHixBpOXPTEztTnXwnE2P9pkbHzQdTltuw8x5MKP+2zRoZQYIu7p
# Zmc6U03dmLq2HnjYNi6cqYJWAAOwBb6J6Gngugnue99qb74py27YP0h1AdkY3m2C
# DPVtI1TkeFN1JFe53Z/zjj3G82jfZfakVqr3lbYoVSfQJL1AoL8ZthISEV09J+BA
# ljis9/kpicO8F7BUhUKz/AyeixmJ5/ALaoHCgRlCGVJ1ijbCHcNhcy4sa3tuPywJ
# eBTpkbKpW99Jo3QMvOyRgNI95ko+ZjtPu4b6MhrZlvSP9pEB9s7GdP32THJvEKt1
# MMU0sHrYUP4KWN1APMdUbZ1jdEgssU5HLcEUBHG/ZPkkvnNtyo4JvbMBV0lUZNlz
# 138eW0QBjloZkWsNn6Qo3GcZKCS6OEuabvshVGtqRRFHqfG3rsjoiV5PndLQTHa1
# V1QJsWkBRH58oWFsc/4Ku+xBZj1p/cvBQUl+fpO+y/g75LcVv7TOPqUxUYS8vwLB
# gqJ7Fx0ViY1w/ue10CgaiQuPNtq6TPmb/wrpNPgkNWcr4A245oyZ1uEi6vAnQj0l
# lOZ0dFtq0Z4+7X6gMTN9vMvpe784cETRkPHIqzqKOghif9lwY1NNje6CbaUFEMFx
# BmoQtB1VM1izoXBm8qGCAs4wggI3AgEBMIH4oYHQpIHNMIHKMQswCQYDVQQGEwJV
# UzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UE
# ChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSUwIwYDVQQLExxNaWNyb3NvZnQgQW1l
# cmljYSBPcGVyYXRpb25zMSYwJAYDVQQLEx1UaGFsZXMgVFNTIEVTTjozRTdBLUUz
# NTktQTI1RDElMCMGA1UEAxMcTWljcm9zb2Z0IFRpbWUtU3RhbXAgU2VydmljZaIj
# CgEBMAcGBSsOAwIaAxUAfemLy/4eAZuNVCzgbfp1HFYG3Q6ggYMwgYCkfjB8MQsw
# CQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9u
# ZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSYwJAYDVQQDEx1NaWNy
# b3NvZnQgVGltZS1TdGFtcCBQQ0EgMjAxMDANBgkqhkiG9w0BAQUFAAIFAOgrwhkw
# IhgPMjAyMzA2MDgxMDU3MjlaGA8yMDIzMDYwOTEwNTcyOVowdzA9BgorBgEEAYRZ
# CgQBMS8wLTAKAgUA6CvCGQIBADAKAgEAAgIF2QIB/zAHAgEAAgISgjAKAgUA6C0T
# mQIBADA2BgorBgEEAYRZCgQCMSgwJjAMBgorBgEEAYRZCgMCoAowCAIBAAIDB6Eg
# oQowCAIBAAIDAYagMA0GCSqGSIb3DQEBBQUAA4GBAKAP48EvVTVm0A+Iswcykzzp
# rgLayr3twHtdtbS2JJJgf1lkLP3qFPLTwAoh96p9CnRKytCPheKc1Cl5O650wcSl
# f+VWBB2xZbytA2tCjATh9YHBwdIKxv5zunGPv4GGLIZ44NNOf28Xp+Ktng5jzY7l
# DPTH2IDBd0FKr1OIl3X5MYIEDTCCBAkCAQEwgZMwfDELMAkGA1UEBhMCVVMxEzAR
# BgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1p
# Y3Jvc29mdCBDb3Jwb3JhdGlvbjEmMCQGA1UEAxMdTWljcm9zb2Z0IFRpbWUtU3Rh
# bXAgUENBIDIwMTACEzMAAAHJ+tWOJSB0Al4AAQAAAckwDQYJYIZIAWUDBAIBBQCg
# ggFKMBoGCSqGSIb3DQEJAzENBgsqhkiG9w0BCRABBDAvBgkqhkiG9w0BCQQxIgQg
# ksCMb8N/ViUA0PPd/UIeV0ErHxssHxw5nFMYjc+BqAcwgfoGCyqGSIb3DQEJEAIv
# MYHqMIHnMIHkMIG9BCCBdc5/Ut1RSxAneCnYf2ANIyGJAP/NfeFdfOHZOXb9gTCB
# mDCBgKR+MHwxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYD
# VQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xJjAk
# BgNVBAMTHU1pY3Jvc29mdCBUaW1lLVN0YW1wIFBDQSAyMDEwAhMzAAAByfrVjiUg
# dAJeAAEAAAHJMCIEIPVQBqqFCJDDLRAClaYQ8cmoLfGCjpRuAiPwdHToQAn5MA0G
# CSqGSIb3DQEBCwUABIICABmWfaWrglKORBHbih39xeSW3ekcj7/eWYiFU1gm49/w
# BzmQwC2IV3+74eyZEyEHxHU3TrZ6Wro2KsuXxY83PcxWuH1BHIIfcmB5PczvaLvp
# 3+GXo99c6N/rgFpn5NF61h5e9x01iYtXYox88Sh5CseUK2hvts3EUkpSBcvWNN3I
# d9P2JwljFDonyQ7dzF7CQwYZGp5JFb1MJ9/4KXrvKn3GMrn1TKlalC243O2YFvJv
# hbY9owTop6e4RxaFOrVig4jXJgfJUB9ZMWOL1IXBxcVUBdHwXL/Oc6p74jWnobSI
# g86Y3nJbM6wy2OeliZMcPEnt7pXbuoh4XeoFplCao0RzdREgGd90PC3CNNeVbH/w
# P88BzT3Oi+r0fqqXyhKrs9dBv55lArZWHS2r0q07Ffb0LF1OMUuv/6IGgWVeKQ0u
# q621wFU6Y32KXF04w6KZ+JV6USmU6sk/UNiht53DBtInZ5bGL675w+zfVyLyHtGB
# LGq7poZdXSusmrquq2hcIAOlDTe13fpQW7eHCUJ2NumS88gh78qz9U4W9LXHwgIq
# fjwy8sV01UfzMnen8KB9NpfnRnJR38x1nJnhK6Ma3CRdo0NT0odigekWQxgNaRT8
# w2pvI5iGduOmAiRT0EEBoNKPEIS1k/dKT8A5WjZKMDBAtbb2DvBw6Fz1OUYuQ9rl
# SIG # End signature block