$ErrorActionPreference='Stop'
Set-StrictMode -Version Latest
$Head='f1b3cdea911b292310c02287d989235225cf4662'
$Repo=(Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$Root=if($env:RUNNER_TEMP){Join-Path $env:RUNNER_TEMP 'gjc12w'}else{'D:\dev\gjc12w'}
$WorkRepo=Join-Path $Root 'repo'
$Output=Join-Path $Root 'output'
$Runner=Join-Path $Root 'g012-owned-runner.mjs'
$Config=Join-Path $Root 'config.json'
$Managed='C:\ProgramData\gjc-remote'
$InventoryBase=Join-Path $Managed 'native'
$ReaderBase=Join-Path $Managed 'native-reader'
$Receipt=Join-Path $Repo 'artifacts\g012-windows-owned-receipt.json'
$CleanupProof=Join-Path $Repo 'artifacts\g012-windows-owned-cleanup.json'
$FailurePath=Join-Path $Repo 'artifacts\g012-windows-owned-failure.log'
$Names=@{M='gjc12w_m';B='gjc12w_b';R='gjc12w_r';D='gjc12w_d'}
$Created=[Collections.Generic.List[string]]::new()
$Failure=$null
function Write-Utf8([string]$Path,[object]$Value){
  $text=if($Value-is[string]){$Value}else{$Value|ConvertTo-Json -Depth 30}
  [IO.File]::WriteAllText($Path,$text,[Text.UTF8Encoding]::new($false))
}
function New-Password {
  $bytes=[byte[]]::new(32);$rng=[Security.Cryptography.RandomNumberGenerator]::Create()
  try{$rng.GetBytes($bytes)}finally{$rng.Dispose()}
  'Aa1!'+[Convert]::ToBase64String($bytes).Replace('/','x').Replace('+','Y')
}
function Invoke-Checked([string]$File,[string[]]$Arguments){
  & $File @Arguments
  if($LASTEXITCODE-ne 0){throw "$File exited $LASTEXITCODE"}
}
function Invoke-As {
  param([Management.Automation.PSCredential]$Credential,[string[]]$Arguments,[string]$Label,[switch]$Async)
  $stdout=Join-Path $Output "$Label.stdout";$stderr=Join-Path $Output "$Label.stderr"
  Remove-Item $stdout,$stderr -Force -ErrorAction SilentlyContinue
  $parameters=@{FilePath='C:\Program Files\nodejs\node.exe';ArgumentList=$Arguments;Credential=$Credential;WorkingDirectory=$Root;LoadUserProfile=$false;RedirectStandardOutput=$stdout;RedirectStandardError=$stderr;PassThru=$true}
  if(-not$Async){$parameters.Wait=$true}
  $process=Start-Process @parameters
  if($Async){return $process}
  $process.Refresh();if($process.ExitCode-ne 0){$detail=if(Test-Path $stderr){Get-Content $stderr -Raw}else{''};throw "$Label exited $($process.ExitCode): $detail"}
  $process
}
function Exact-Acl([string]$Path,[string]$Owner,[string]$Reader1,[string]$Reader2){
  New-Item -ItemType Directory -Path $Path -Force|Out-Null
  Invoke-Checked icacls.exe @($Path,'/setowner',"*$Owner")
  Invoke-Checked icacls.exe @($Path,'/inheritance:r','/grant:r',"*$Owner`:(F)",'*S-1-5-18:(F)',"*$Reader1`:(RX)","*$Reader2`:(RX)")
}
function Remove-Protected([string]$Path){
  if(-not(Test-Path $Path)){return}
  & takeown.exe /F $Path /A /R /D Y|Out-Null
  & icacls.exe $Path /grant '*S-1-5-32-544:(OI)(CI)F' /T /C /Q|Out-Null
  & $env:ComSpec /d /c "rmdir /s /q `"$Path`""
}
function Read-Json([string]$Name){Get-Content (Join-Path $Output $Name) -Raw|ConvertFrom-Json}
try{
  $identity=[Security.Principal.WindowsIdentity]::GetCurrent();$principal=[Security.Principal.WindowsPrincipal]$identity
  if(-not$principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)){throw 'administrator token required'}
  if((Test-Path $Root) -or (Test-Path $InventoryBase) -or (Test-Path $ReaderBase)){throw 'fixture path already exists'}
  foreach($name in $Names.Values){if(Get-LocalUser $name -ErrorAction SilentlyContinue){throw "fixture user exists: $name"}}
  New-Item -ItemType Directory -Path $Root,$Output -Force|Out-Null
  $credentials=@{};$sids=@{}
  foreach($role in 'M','B','R','D'){
    $plain=New-Password;$secure=[Security.SecureString]::new()
    foreach($character in $plain.ToCharArray()){$secure.AppendChar($character)}
    $secure.MakeReadOnly();$plain=$null
    $name=$Names[$role];New-LocalUser -Name $name -Password $secure -AccountNeverExpires -PasswordNeverExpires -UserMayNotChangePassword|Out-Null
    $Created.Add($name);$credentials[$role]=[Management.Automation.PSCredential]::new("$env:COMPUTERNAME\$name",$secure)
    $sids[$role]=(Get-LocalUser $name).SID.Value.ToUpperInvariant()
  }
  Invoke-Checked git.exe @('clone','--quiet','--no-checkout','https://github.com/kogangdon/gjc-remote.git',$WorkRepo)
  Invoke-Checked git.exe @('-C',$WorkRepo,'checkout','--quiet',$Head)
  Push-Location $WorkRepo
  try{
    Invoke-Checked bun.exe @('install','--frozen-lockfile','--ignore-scripts')
    Invoke-Checked npm.cmd @('run','build','--workspace','@gjc-remote/native-control')
  }finally{Pop-Location}
  Copy-Item (Join-Path $Repo 'artifacts\g012-owned-runner.mjs') $Runner
  Invoke-Checked icacls.exe @($Root,'/grant',"*$($sids.M)`:(OI)(CI)(RX)","*$($sids.D)`:(OI)(CI)(RX)")
  $hostId='g012-windows-owned';$sha=[Security.Cryptography.SHA256]::Create()
  try{$hostKey=([BitConverter]::ToString($sha.ComputeHash([Text.Encoding]::UTF8.GetBytes($hostId)))).Replace('-','').ToLowerInvariant()}finally{$sha.Dispose()}
  $inventory=Join-Path $InventoryBase $hostKey;$reader=Join-Path $ReaderBase $hostKey
  New-Item -ItemType Directory -Path $inventory,$reader -Force|Out-Null
  Exact-Acl $inventory $sids.M $sids.D $sids.R;Exact-Acl $InventoryBase $sids.M $sids.D $sids.R
  Exact-Acl $reader $sids.D $sids.M $sids.R;Exact-Acl $ReaderBase $sids.D $sids.M $sids.R
  $configValue=[ordered]@{repo=$WorkRepo;addonPath=(Join-Path $WorkRepo 'native-control\build\Release\native_control.node');hostId=$hostId;hostKey=$hostKey;ready=(Join-Path $Root 'ready');roles=[ordered]@{management=[ordered]@{kind='sid';value=$sids.M};bot=[ordered]@{kind='sid';value=$sids.B};recovery=[ordered]@{kind='sid';value=$sids.R};daemon=[ordered]@{kind='sid';value=$sids.D};system=[ordered]@{kind='sid';value='S-1-5-18'}}}
  Write-Utf8 $Config $configValue
  $genesis=Join-Path $Root 'genesis.json';$unchanged=Join-Path $Root 'unchanged.json';$pending=Join-Path $Root 'pending.json';$unchanged2=Join-Path $Root 'unchanged2.json'
  Write-Utf8 $genesis ([ordered]@{hostId=$hostId;expectedInventoryGeneration=0;workspaces=@([ordered]@{workspaceId='repo';sourcePlatform='windows-drive';workDir=$WorkRepo})})
  Write-Utf8 $unchanged ([ordered]@{hostId=$hostId;expectedInventoryGeneration=1;workspaces=@([ordered]@{workspaceId='repo';sourcePlatform='windows-drive';workDir=$WorkRepo})})
  Write-Utf8 $pending ([ordered]@{hostId=$hostId;expectedInventoryGeneration=1;workspaces=@()})
  Write-Utf8 $unchanged2 ([ordered]@{hostId=$hostId;expectedInventoryGeneration=2;workspaces=@()})
  Invoke-As $credentials.M @("`"$Runner`"","`"$Config`"",'publish-allow-error',"`"$(Join-Path $Output 'genesis.json')`"","`"$genesis`"") 'genesis'|Out-Null
  Invoke-As $credentials.M @("`"$Runner`"","`"$Config`"",'publish-allow-error',"`"$(Join-Path $Output 'unchanged.json')`"","`"$unchanged`"") 'unchanged'|Out-Null
  Invoke-As $credentials.M @("`"$Runner`"","`"$Config`"",'publish-allow-error',"`"$(Join-Path $Output 'pending.json')`"","`"$pending`"") 'pending'|Out-Null
  Invoke-As $credentials.D @("`"$Runner`"","`"$Config`"",'floor',"`"$(Join-Path $Output 'floor.json')`"") 'floor'|Out-Null
  Invoke-As $credentials.M @("`"$Runner`"","`"$Config`"",'publish-allow-error',"`"$(Join-Path $Output 'replacement.json')`"","`"$pending`"") 'replacement'|Out-Null
  $ready=$configValue.ready;Write-Utf8 $ready ''
  Invoke-Checked icacls.exe @($ready,'/inheritance:r','/grant:r',"*$($sids.D)`:(M)",'*S-1-5-18:(F)')
  $holder=Invoke-As $credentials.D @("`"$Runner`"","`"$Config`"",'hold',"`"$(Join-Path $Output 'holder.json')`"") 'holder' -Async
  $deadline=[DateTime]::UtcNow.AddSeconds(10);while((Get-Item $ready).Length-eq 0-and[DateTime]::UtcNow-lt$deadline){Start-Sleep -Milliseconds 100}
  if((Get-Item $ready).Length-eq 0){throw 'D holder did not become ready'}
  $clock=[Diagnostics.Stopwatch]::StartNew();Invoke-As $credentials.M @("`"$Runner`"","`"$Config`"",'publish-allow-error',"`"$(Join-Path $Output 'blocked.json')`"","`"$unchanged2`"") 'blocked'|Out-Null;$clock.Stop()
  $holder.WaitForExit();if($holder.ExitCode-ne 0){throw 'D holder failed'}
  Invoke-As $credentials.M @("`"$Runner`"","`"$Config`"",'corrupt-commit',"`"$(Join-Path $Output 'corrupt.json')`"") 'corrupt'|Out-Null
  Invoke-As $credentials.M @("`"$Runner`"","`"$Config`"",'publish-allow-error',"`"$(Join-Path $Output 'marker.json')`"","`"$unchanged2`"") 'marker'|Out-Null
  $evidence=[ordered]@{schemaVersion=1;status='passed';head=$Head;platform='Windows 11 Pro x64 NTFS';principals=[ordered]@{M=$sids.M;B=$sids.B;R=$sids.R;D=$sids.D;SYSTEM='S-1-5-18'};genesis=(Read-Json 'genesis.json');unchanged=(Read-Json 'unchanged.json');pending=(Read-Json 'pending.json');floor=(Read-Json 'floor.json');replacement=(Read-Json 'replacement.json');dFenceBlockedMs=$clock.ElapsedMilliseconds;blockedUnchanged=(Read-Json 'blocked.json');holder=(Read-Json 'holder.json');markerFailure=(Read-Json 'marker.json');inventoryFiles=@(Get-ChildItem $inventory -Force|Select-Object -ExpandProperty Name);readerFiles=@(Get-ChildItem $reader -Force|Select-Object -ExpandProperty Name)}
  if($evidence.genesis.status-ne'published'-or$evidence.genesis.writes-ne 11){throw 'genesis receipt mismatch'}
  if($evidence.unchanged.status-ne'unchanged'-or$evidence.unchanged.writes-ne 0){throw 'unchanged receipt mismatch'}
  if($evidence.pending.code-ne'INVENTORY_PENDING'-or$evidence.pending.writes-ne 0){throw 'pending receipt mismatch'}
  if($evidence.floor.writes-ne 4){throw 'floor receipt mismatch'}
  if($evidence.replacement.inventoryGeneration-ne 2-or$evidence.replacement.writes-ne 10){throw 'replacement receipt mismatch'}
  if($evidence.dFenceBlockedMs-lt 2500-or$evidence.blockedUnchanged.status-ne'unchanged'){throw 'D fence serialization mismatch'}
  if($evidence.markerFailure.code-ne'INVENTORY_MANUAL_CLEANUP'-or$evidence.markerFailure.writes-ne 4){throw 'marker receipt mismatch'}
  Write-Utf8 $Receipt $evidence
}catch{$Failure=$_;Write-Utf8 $FailurePath $_.Exception.ToString()}finally{
  Remove-Protected $InventoryBase;Remove-Protected $ReaderBase;Remove-Protected $Root
  foreach($name in $Created){Remove-LocalUser $name -ErrorAction SilentlyContinue}
  $users=@(Get-LocalUser|Where-Object Name -like 'gjc12w_*')
  $proof=[ordered]@{schemaVersion=1;status=if((-not(Test-Path $InventoryBase))-and(-not(Test-Path $ReaderBase))-and(-not(Test-Path $Root))-and$users.Count-eq 0){'passed'}else{'failed'};inventoryRootAbsent=(-not(Test-Path $InventoryBase));readerRootAbsent=(-not(Test-Path $ReaderBase));fixtureRootAbsent=(-not(Test-Path $Root));usersAbsent=($users.Count-eq 0)}
  Write-Utf8 $CleanupProof $proof
}
if($Failure){throw $Failure}
'G012_WINDOWS_OWNED_PASS'
