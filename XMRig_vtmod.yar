import "vt"

rule xmrig_suspicious_behaviour {
  meta:
   author = "Jesus Toledano"
    creation_date = "2023-12-11"
    threat_name = "cryptominer"
    reference_sample = "770eff289f8f90590f44e1c8a05a00079717ded32aff660f127dfdabe79a5c6b"
    reference_sample = "fa220ddd2bfaaf501f761bb9774c591d16fff4b6220c758e6202eb2eff7bf7c6"
    severity = 100
    vt_collection = "https://www.virustotal.com/gui/collection/ae52a578b40ba0cac6f2a13b6d43e2a25560799139b5c90b1bce8f164d0f7b38/summary"

    /*
    vti search:

    (behaviour_registry:"<HKLM>\SOFTWARE\WOW6432NODE\MICROSOFT\WINDOWS\CURRENTVERSION\POLICIES\SYSTEM\DISABLETASKMGR" 
    AND behaviour_registry:"<HKLM>\SOFTWARE\MICROSOFT\WINDOWS\CURRENTVERSION\POLICIES\SYSTEM\DISABLETASKMGR")
    OR behaviour:"%windir%\\System32\\findstr.exe /i /c:\"xmrig\""
    OR (behaviour:"%windir%\\System32\\attrib.exe -h -r -s \"%ProgramData%\\USOShared\\*.*\" "
    AND behaviour:"powershell.exe")

    search link:
    https://www.virustotal.com/gui/search/(behaviour_registry%253A%2522%253CHKLM%253E%255CSOFTWARE%255CWOW6432NODE%255CMICROSOFT%255CWINDOWS%255CCURRENTVERSION%255CPOLICIES%255CSYSTEM%255CDISABLETASKMGR%2522%2520%2520AND%2520behaviour_registry%253A%2522%253CHKLM%253E%255CSOFTWARE%255CMICROSOFT%255CWINDOWS%255CCURRENTVERSION%255CPOLICIES%255CSYSTEM%255CDISABLETASKMGR%2522)%2520OR%2520behaviour%253A%2522%2525windir%2525%255C%255CSystem32%255C%255Cfindstr.exe%2520%252Fi%2520%252Fc%253A%255C%2522xmrig%255C%2522%2522%2520OR%2520(behaviour%253A%2522%2525windir%2525%255C%255CSystem32%255C%255Cattrib.exe%2520-h%2520-r%2520-s%2520%255C%2522%2525ProgramData%2525%255C%255CUSOShared%255C%255C*.*%255C%2522%2520%2522%2520AND%2520behaviour%253A%2522powershell.exe%2522)
    
    */
  condition:
    (
        for any vt_behaviour_registry_keys_set in vt.behaviour.registry_keys_set: (
            vt_behaviour_registry_keys_set.key == "HKLM\\Software\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\DisableTaskMgr"
        )
        and for any vt_behaviour_registry_keys_set in vt.behaviour.registry_keys_set: (
            vt_behaviour_registry_keys_set.key == "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\DisableTaskMgr"
        )
    ) or
        for any vt_behaviour_processes_terminated in vt.behaviour.processes_terminated: (
            vt_behaviour_processes_terminated == "%windir%\\System32\\findstr.exe /i /c:\"xmrig\""
    ) 
    or (
        for any vt_behaviour_processes_terminated in vt.behaviour.processes_terminated: (
            vt_behaviour_processes_terminated contains "%windir%\\System32\\attrib.exe -h -r -s \"%ProgramData%\\USOShared\\*.*\" "
        )
        and for any vt_behaviour_processes_injected in vt.behaviour.processes_injected: (
            vt_behaviour_processes_injected == "powershell.exe"
        )
    )
}
