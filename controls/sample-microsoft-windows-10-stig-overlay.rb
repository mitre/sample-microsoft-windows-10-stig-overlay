
include_controls 'microsoft-windows-10-stig-baseline' do
  control 'V-63321' do
    impact 0.0
    desc 'caveat', 'This is Not Applicable since the related security control is not included in ***SPONSOR*** policy'
  end
  control 'V-63325' do
    impact 0.0
    desc 'caveat', 'This is Not Applicable since the related security control is not included in ***SPONSOR*** policy'
  end
  control 'V-63335' do
    impact 0.0
    desc 'caveat', 'This is Not Applicable since the related security control is not included in ***SPONSOR*** policy'
  end
  control 'V-63337' do
    if sys_info.manufacturer == 'VMware, Inc.'
      impact 0.0
      describe 'This is a VDI System; This System is NA for Control V-63337.' do
        skip 'This is a VDI System; This System is NA for Control V-63337.'
      end
    else
      query = json({ command: 'Get-BitlockerVolume | Select ProtectionStatus | ConvertTo-Json' })
      describe 'Verify all Windows 10 information systems (including SIPRNET) employ BitLocker for full disk encryption.' do
        subject { query.params.first }
        its(['ProtectionStatus']) { should be 1 }
      end
    end
  end
  control 'V-63339' do
    impact 0.0
    desc 'caveat', 'This is Not Applicable since the related security control is not included in ***SPONSOR*** policy'
  end
  control 'V-63341' do
    impact 0.0
    desc 'caveat', 'This is Not Applicable since the related security control is not included in ***SPONSOR*** policy'
  end
  control 'V-63343' do
    impact 0.0
    desc 'caveat', 'This is Not Applicable since the related security control is not included in ***SPONSOR*** policy'
  end
  control 'V-63345' do
    impact 0.0
    desc 'caveat', 'This is Not Applicable since the related security control is not included in ***SPONSOR*** policy'
  end
  control 'V-63347' do
    impact 0.0
    desc 'caveat', 'This is Not Applicable since the related security control is not included in ***SPONSOR*** policy'
  end
  control 'V-63369' do
    impact 0.0
    desc 'caveat', 'This is Not Applicable since the related security control is not included in ***SPONSOR*** policy'
  end
  control 'V-63375' do
    impact 0.0
    desc 'caveat', 'This is Not Applicable since the related security control is not included in ***SPONSOR*** policy'
  end
  control 'V-63431' do
    impact 0.0
    desc 'caveat', 'This is Not Applicable since the related security control is not included in ***SPONSOR*** policy'
  end
  control 'V-63435' do
    impact 0.0
    desc 'caveat', 'This is Not Applicable since the related security control is not included in ***SPONSOR*** policy'
  end
  control 'V-63445' do
    impact 0.0
    desc 'caveat', 'This is Not Applicable since the related security control is not included in ***SPONSOR*** policy'
  end
  control 'V-63447' do
    impact 0.0
    desc 'caveat', 'This is Not Applicable since the related security control is not included in ***SPONSOR*** policy'
  end
  control 'V-63449' do
    impact 0.0
    desc 'caveat', 'This is Not Applicable since the related security control is not included in ***SPONSOR*** policy'
  end
  control 'V-63451' do
    impact 0.0
    desc 'caveat', 'This is Not Applicable since the related security control is not included in ***SPONSOR*** policy'
  end
  control 'V-63453' do
    impact 0.0
    desc 'caveat', 'This is Not Applicable since the related security control is not included in ***SPONSOR*** policy'
  end
  control 'V-63457' do
    impact 0.0
    desc 'caveat', 'This is Not Applicable since the related security control is not included in ***SPONSOR*** policy'
  end
  control 'V-63459' do
    impact 0.0
    desc 'caveat', 'This is Not Applicable since the related security control is not included in ***SPONSOR*** policy'
  end
  control 'V-63463' do
    impact 0.0
    desc 'caveat', 'This is Not Applicable since the related security control is not included in ***SPONSOR*** policy'
  end
  control 'V-63467' do
    impact 0.0
    desc 'caveat', 'This is Not Applicable since the related security control is not included in ***SPONSOR*** policy'
  end
  control 'V-63469' do
    impact 0.0
    desc 'caveat', 'This is Not Applicable since the related security control is not included in ***SPONSOR*** policy'
  end
  control 'V-63471' do
    impact 0.0
    desc 'caveat', 'This is Not Applicable since the related security control is not included in ***SPONSOR*** policy'
  end
  control 'V-63473' do
    impact 0.0
    desc 'caveat', 'This is Not Applicable since the related security control is not included in ***SPONSOR*** policy'
  end
  control 'V-63479' do
    impact 0.0
    desc 'caveat', 'This is Not Applicable since the related security control is not included in ***SPONSOR*** policy'
  end
  control 'V-63481' do
    impact 0.0
    desc 'caveat', 'This is Not Applicable since the related security control is not included in ***SPONSOR*** policy'
  end
  control 'V-63483' do
    impact 0.0
    desc 'caveat', 'This is Not Applicable since the related security control is not included in ***SPONSOR*** policy'
  end
  control 'V-63487' do
    impact 0.0
    desc 'caveat', 'This is Not Applicable since the related security control is not included in ***SPONSOR*** policy'
  end
  control 'V-63491' do
    impact 0.0
    desc 'caveat', 'This is Not Applicable since the related security control is not included in ***SPONSOR*** policy'
  end
  control 'V-63499' do
    impact 0.0
    desc 'caveat', 'This is Not Applicable since the related security control is not included in ***SPONSOR*** policy'
  end
  control 'V-63503' do
    impact 0.0
    desc 'caveat', 'This is Not Applicable since the related security control is not included in ***SPONSOR*** policy'
  end
  control 'V-63507' do
    impact 0.0
    desc 'caveat', 'This is Not Applicable since the related security control is not included in ***SPONSOR*** policy'
  end
  control 'V-63513' do
    impact 0.0
    desc 'caveat', 'This is Not Applicable since the related security control is not included in ***SPONSOR*** policy'
  end
  control 'V-63515' do
    impact 0.0
    desc 'caveat', 'This is Not Applicable since the related security control is not included in ***SPONSOR*** policy'
  end
  control 'V-63517' do
    impact 0.0
    desc 'caveat', 'This is Not Applicable since the related security control is not included in ***SPONSOR*** policy'
  end
  control 'V-63519' do
    impact 0.0
    desc 'caveat', 'This is Not Applicable since the related security control is not included in ***SPONSOR*** policy'
  end
  control 'V-63523' do
    impact 0.0
    desc 'caveat', 'This is Not Applicable since the related security control is not included in ***SPONSOR*** policy'
  end
  control 'V-63527' do
    impact 0.0
    desc 'caveat', 'This is Not Applicable since the related security control is not included in ***SPONSOR*** policy'
  end
  control 'V-63533' do
    impact 0.0
    desc 'caveat', 'This is Not Applicable since the related security control is not included in ***SPONSOR*** policy'
  end
  control 'V-63537' do
    impact 0.0
    desc 'caveat', 'This is Not Applicable since the related security control is not included in ***SPONSOR*** policy'
  end
  control 'V-63541' do
    impact 0.0
    desc 'caveat', 'This is Not Applicable since the related security control is not included in ***SPONSOR*** policy'
  end
  control 'V-63579' do
    impact 0.0
    desc 'caveat', 'This is Not Applicable since the related security control is not included in ***SPONSOR*** policy'
  end
  control 'V-63583' do
    impact 0.0
    desc 'caveat', 'This is Not Applicable since the related security control is not included in ***SPONSOR*** policy'
  end
  control 'V-63587' do
    impact 0.0
    desc 'caveat', 'This is Not Applicable since the related security control is not included in ***SPONSOR*** policy'
  end
  control 'V-63589' do
    impact 0.0
    desc 'caveat', 'This is Not Applicable since the related security control is not included in ***SPONSOR*** policy'
  end
  control 'V-63635' do
    impact 0.0
    desc 'caveat', 'This is Not Applicable since the related security control is not included in ***SPONSOR*** policy'
  end
  control 'V-63645' do
    impact 0.0
    desc 'caveat', 'This is Not Applicable since the related security control is not included in ***SPONSOR*** policy'
  end
  control 'V-63649' do
    impact 0.0
    desc 'caveat', 'This is Not Applicable since the related security control is not included in ***SPONSOR*** policy'
  end
  control 'V-63669' do
    impact 0.0
    desc 'caveat', 'This is Not Applicable since the related security control is not included in ***SPONSOR*** policy'
  end
  control 'V-63675' do
    impact 0.0
    desc 'caveat', 'This is Not Applicable since the related security control is not included in ***SPONSOR*** policy'
  end
  control 'V-63681' do
    impact 0.0
    desc 'caveat', 'This is Not Applicable since the related security control is not included in ***SPONSOR*** policy'
  end
  control 'V-63689' do
    impact 0.0
    desc 'caveat', 'This is Not Applicable since the related security control is not included in ***SPONSOR*** policy'
  end
  control 'V-63729' do
    impact 0.0
    desc 'caveat', 'This is Not Applicable since the related security control is not included in ***SPONSOR*** policy'
  end
  control 'V-63733' do
    impact 0.0
    desc 'caveat', 'This is Not Applicable since the related security control is not included in ***SPONSOR*** policy'
  end
  control 'V-63737' do
    impact 0.0
    desc 'caveat', 'This is Not Applicable since the related security control is not included in ***SPONSOR*** policy'
  end
  control 'V-63741' do
    impact 0.0
    desc 'caveat', 'This is Not Applicable since the related security control is not included in ***SPONSOR*** policy'
  end
  control 'V-63817' do
    impact 0.0
    desc 'caveat', 'This is Not Applicable since the related security control is not included in ***SPONSOR*** policy'
  end
  control 'V-63821' do
    impact 0.0
    desc 'caveat', 'This is Not Applicable since the related security control is not included in ***SPONSOR*** policy'
  end
  control 'V-63829' do
    impact 0.0
    desc 'caveat', 'This is Not Applicable since the related security control is not included in ***SPONSOR*** policy'
  end
  control 'V-63879' do
    impact 0.0
    desc 'caveat', 'This is Not Applicable since the related security control is not included in ***SPONSOR*** policy'
  end
  control 'V-63927' do
    impact 0.0
    desc 'caveat', 'This is Not Applicable since the related security control is not included in ***SPONSOR*** policy'
  end
  control 'V-68817' do
    impact 0.0
    desc 'caveat', 'This is Not Applicable since the related security control is not included in ***SPONSOR*** policy'
  end
  control 'V-68819' do
    impact 0.0
    desc 'caveat', 'This is Not Applicable since the related security control is not included in ***SPONSOR*** policy'
  end
  control 'V-68845' do
    impact 0.0
    desc 'caveat', 'This is Not Applicable since the related security control is not included in ***SPONSOR*** policy'
  end
  control 'V-68849' do
    impact 0.0
    desc 'caveat', 'This is Not Applicable since the related security control is not included in ***SPONSOR*** policy'
  end
  control 'V-71759' do
    impact 0.0
    desc 'caveat', 'This is Not Applicable since the related security control is not included in ***SPONSOR*** policy'
  end
  control 'V-71761' do
    impact 0.0
    desc 'caveat', 'This is Not Applicable since the related security control is not included in ***SPONSOR*** policy'
  end
  control 'V-74409' do
    impact 0.0
    desc 'caveat', 'This is Not Applicable since the related security control is not included in ***SPONSOR*** policy'
  end
  control 'V-74411' do
    impact 0.0
    desc 'caveat', 'This is Not Applicable since the related security control is not included in ***SPONSOR*** policy'
  end
  control 'V-74721' do
    impact 0.0
    desc 'caveat', 'This is Not Applicable since the related security control is not included in ***SPONSOR*** policy'
  end
  control 'V-75027' do
    impact 0.0
    desc 'caveat', 'This is Not Applicable since the related security control is not included in ***SPONSOR*** policy'
  end
  control 'V-77095' do
    impact 0.0
    desc 'caveat', 'This is Not Applicable since the related security control is not included in ***SPONSOR*** policy'
  end
  control 'V-94719' do
    impact 0.0
    desc 'caveat', 'This is Not Applicable since the related security control is not included in ***SPONSOR*** policy'
  end
  control 'V-99541' do
    impact 0.0
    desc 'caveat', 'This is Not Applicable since the related security control is not included in ***SPONSOR*** policy'
  end
  control 'V-99543' do
    impact 0.0
    desc 'caveat', 'This is Not Applicable since the related security control is not included in ***SPONSOR*** policy'
  end
  control 'V-99545' do
    impact 0.0
    desc 'caveat', 'This is Not Applicable since the related security control is not included in ***SPONSOR*** policy'
  end
  control 'V-99547' do
    impact 0.0
    desc 'caveat', 'This is Not Applicable since the related security control is not included in ***SPONSOR*** policy'
  end
  control 'V-99549' do
    impact 0.0
    desc 'caveat', 'This is Not Applicable since the related security control is not included in ***SPONSOR*** policy'
  end
  control 'V-99551' do
    impact 0.0
    desc 'caveat', 'This is Not Applicable since the related security control is not included in ***SPONSOR*** policy'
  end
  control 'V-99553' do
    impact 0.0
    desc 'caveat', 'This is Not Applicable since the related security control is not included in ***SPONSOR*** policy'
  end
  control 'V-102627' do
    title "Windows 10 must use multifactor authentication for local and network access to     
          privileged and non-privileged accounts."
    desc "Without the use of multifactor authentication, the ease of access to privileged and 
          non-privileged functions is greatly increased. 

          All domain accounts must be enabled for multifactor authentication with the exception of local emergency accounts. 
        
          Multifactor authentication requires using two or more factors to achieve authentication.
        
          Factors include: 
        
          1) Something a user knows (e.g., password/PIN);
        
          2) Something a user has (e.g., cryptographic identification device, token); and
        
          3) Something a user is (e.g., biometric).
        
          A privileged account is defined as an information system account with authorizations of a privileged user.
        
          Network access is defined as access to an information system by a user (or a process acting on behalf of a user) communicating through a network (e.g., local area network, wide area network, or the Internet).
        
          Local access is defined as access to an organizational information system by a user (or process acting on behalf of a user) communicating through a direct connection without the use of a network.
        
          The DoD CAC with DoD-approved PKI is an example of multifactor authentication."

    impact 0.5
    tag severity: 'medium'
    tag gtitle: 'SRG-OS-000105-GPOS-00052'
    tag gid: 'V-102627'
    tag rid: 'SV-220946r569187_rule'
    tag stig_id: 'WN10-SO-000251'
    tag fix_id: 'F-69379r1_fix'
    tag cci: ['CCI-000765']
    tag nist: ['IA-2 (1)', 'Rev_4']
    tag false_negatives: nil
    tag false_positives: nil
    tag documentable: false
    tag mitigations: nil
    tag severity_override_guidance: false
    tag potential_impacts: nil
    tag third_party_tools: nil
    tag mitigation_controls: nil
    tag responsibility: nil
    tag ia_controls: nil

    desc "check", "If the system is a member of a domain this is Not Applicable.

          If one of the following settings does not exist and is not populated, this is a finding: 
          
          Computer\HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Cryptography\Calais\Readers
          Computer\HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Cryptography\Calais\SmartCards"

    desc "fix", "For non-domain joined systems, configuring Windows Hello for sign on options
          would be suggested based on the organizations needs and capabilities.

          Note: Before applying, the supplemental guidance provided with the STIG should be consulted to ensure continued access to the operating system."

    smartcard_registry_key = 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Cryptography\Calais\SmartCards'
    reader_registry_key = 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Cryptography\Calais\Readers'
    
    is_domain = command('wmic computersystem get domain | FINDSTR /V Domain').stdout.strip

    if is_domain == 'WORKGROUP'
      describe registry_key(smartcard_registry_key) do
        it { should exist }
        its('children') { should_not eq [] }
      end
      describe registry_key(reader_registry_key) do
        it { should exist }
        its('children') { should_not eq [] }
      end
    else
      impact 0.0
      describe 'The system is a member of a domain, control is NA' do
        skip 'The system is a member of a domain, control is NA'
      end
    end
  end
end

