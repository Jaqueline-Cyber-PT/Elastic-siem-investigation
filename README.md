## Investigação de Comprometimento de Domínio e Escalação de Privilégios (Lab Infinity)

Este repositório documenta a investigação forense de um ataque de escalada de privilégios em um ambiente Windows Server 2016, monitorado via **Elastic SIEM**. A análise percorre desde o ruído inicial de um ataque de força bruta até o silêncio perigoso da persistência via serviços do sistema.

### O Cenário:

- **Ambiente:** Active Directory (Windows Server 2016)
- **Ferramentas de Defesa:** Elastic Stack (SIEM), Winlogbeat
- **Vítima:** Domínio `REDCLOUD.TRAINING`

| Horário | Evento | Descrição | Status |
| :--- | :--- | :--- | :--- |
| 12:46:00 | Reconhecimento | Tentativas de login distribuídas (Password Spraying). | 🔴 Detectado |
| 12:46:50 | Acesso Inicial | Comprometimento da conta helpdesk1. | ⚠️ Sucesso |
| 12:47:16 | Escalada | Promoção para a conta system_admin. | ⚠️ Crítico |
| 12:47:55 | Persistência | Manipulação do Service Control Manager (svcctl). | 🔎 Investigando |
| 12:50:00 | Domínio Total | Inclusão de usuário no grupo Domain Admins. | 🛑 Comprometido |

## Atos da Investigação

### Ato I: Reconhecimento Adversário e Detecção de Password Spraying
- *Técnica MITRE: T1110.003*

Para identificar o vetor de ataque inicial, apliquei no Elastic SIEM o filtro `event.provider:"Microsoft-Windows-Security-Auditing" and winlog.event_id:"4625" and winlog.event_data.LogonType:"3"` o que revelou um volume anômalo de falhas de logon de rede originadas do IP **172.16.98.100** direcionadas a múltiplos usuários como administrador e suporte. A análise técnica dos campos `user.name` e `source.ip` confirmou uma técnica de Brute Force onde o adversário testa credenciais comuns contra diversas contas simultaneamente para evitar gatilhos de bloqueio (lockout), caracterizando a fase de reconhecimento e tentativa de acesso inicial. 

Como próximo passo investigativo, é necessário executar a query `event.code: 4624` vinculada ao mesmo IP atacante para validar se algum desses disparos obteve sucesso, identificando assim a conta "Paciente Zero" que serviu de porta de entrada para a rede.

<img width="1915" height="769" alt="image" src="https://github.com/user-attachments/assets/5bbb1db0-6769-4b06-a520-7e44e010e366" />

### Ato II: Quebra de Perímetro e Identificação do Foothold

Para confirmar se o ataque de pulverização obteve êxito, executei a query `event.provider:"Microsoft-Windows-Security-Auditing" and winlog.event_id:4624 and winlog.event_data.LogonType:"3" 
and related.ip : "172.16.98.100"` filtrando apenas por logons de rede bem-sucedidos originados da fonte agressora. A busca revelou um evento de "Auditoria de Sucesso" para o usuário **helpdesk1**, confirmando que o atacante obteve o primeiro ponto de apoio (foothold) dentro da infraestrutura REDCLOUD através de uma credencial legítima, porém comprometida. 

A análise técnica do campo `TargetLogonId` permitiu estabelecer uma âncora para correlacionar todas as atividades subsequentes desta sessão, evidenciando que a conta de suporte técnico foi o vetor utilizado para iniciar a exploração interna. Como próximo passo, é fundamental rastrear processos iniciados por essa conta para identificar ferramentas de busca por credenciais administrativas ou movimentação lateral.

<img width="1901" height="864" alt="image" src="https://github.com/user-attachments/assets/f8b54aa8-4b19-4f02-adde-5891f65b4b35" />

### Ato III: Escalada de Privilégios e Promoção do Adversário

A investigação avançou para a detecção de elevação de privilégios ao monitorar novos logons a partir do mesmo IP, identificando a conta **system_admin** através da query `event.provider:"Microsoft-Windows-Security-Auditing" and winlog.event_id:4672 and user.name:"system_admin"`. A análise da linha do tempo revelou que o acesso administrativo ocorreu apenas minutos após a entrada inicial, um padrão clássico de **Credential Dumping**, onde o invasor provavelmente extraiu hashes de senhas da memória (LSASS) da estação onde o helpdesk estava logado. 

Este salto crítico de privilégio transformou um acesso de usuário comum em um controle de nível administrativo, permitindo ao atacante interagir com funções sensíveis do sistema. O próximo passo investigativo foca na validação de quais direitos administrativos foram efetivamente exercidos sobre o Controlador de Domínio.


<img width="1901" height="882" alt="image" src="https://github.com/user-attachments/assets/06ab373c-d15a-43f2-b70f-1de0fd0c9c07" />

### Ato IV: Persistência no Active Directory via Manipulação de ACL

A consolidação do controle sobre o domínio foi identificada através da query `event.provider:"Microsoft-Windows-Security-Auditing" and winlog.event_id:5136 and winlog.event_data.AttributeLDAPDisplayName:"nTSecurityDescriptor"`, monitorando mudanças nas permissões de objetos críticos. A análise técnica revelou que o atacante modificou a Lista de Controle de Acesso (ACL) do grupo **Domain Admins**, alterando o descritor de segurança para permitir que contas sob seu controle pudessem gerenciar o grupo de forma arbitrária.

Esta técnica de **ACL Backdooring** é extremamente perigosa, pois permite ao invasor reaver privilégios administrativos mesmo após um reset de senha ou remoção de membros, garantindo uma persistência silenciosa no nível mais alto do diretório. O próximo passo do adversário, após "ser dono da chave", é efetivamente adicionar um usuário ao grupo para formalizar sua autoridade.

<img width="1910" height="713" alt="image" src="https://github.com/user-attachments/assets/6ebfe3cb-b570-4caa-8328-cb09ee30affc" />

### Ato V: Elevação de Privilégios via Associação Forçada ao Grupo

Com a "fechadura" do grupo alterada no ato anterior, o atacante executou a promoção definitiva utilizando a query `event.provider:"Microsoft-Windows-Security-Auditing" and winlog.event_id:4728 and winlog.event_data.TargetUserName:"Domain Admins"`. O log revelou o momento exato em que um usuário foi adicionado ao grupo de segurança mais sensível da organização, confirmando o **Domain Dominance**. Diferente de um processo administrativo legítimo, esta ação ocorreu imediatamente após a manipulação da ACL, evidenciando um uso indevido deliberado de acesso privilegiado para garantir controle total sobre a infraestrutura.

<img width="1914" height="855" alt="image" src="https://github.com/user-attachments/assets/9ecf5799-8f3d-47ae-a970-1593fe2754b1" />

### Ato VI: Movimentação Lateral e Enumeração via IPC$
Após garantir privilégios de domínio, o adversário iniciou a fase de exploração operacional utilizando, informação adquirida com a query `event.provider:"Microsoft-Windows-Security-Auditing" and winlog.event_id:"5140" and user.name:"system_admin" `. A análise técnica revelou que o usuário comprometido acessou o compartilhamento oculto IPC$ (Inter-Process Communication) a partir do IP atacante, um comportamento clássico de ferramentas como PsExec ou Impacket. 

Esse acesso ao "Named Pipe" é o precursor necessário para a execução remota de comandos e a enumeração de serviços no Controlador de Domínio, servindo como a ponte final para o controle total do sistema operacional. 

<img width="1831" height="857" alt="image" src="https://github.com/user-attachments/assets/3e2fb7fc-214b-4836-ad30-3bfe6b9f3ae9" />

### Ato VII: Interação com o Pipe `svcctl` e Preparação de Execução Remota

Para identificar a tentativa de execução de comandos, apliquei a query `event.provider:"Microsoft-Windows-Security-Auditing" and winlog.event_id:"5145" and user.name:"system_admin"`, focando no acesso detalhado a objetos de rede. A análise técnica revelou que o usuário comprometido solicitou uma máscara de acesso **0x83** (Read/Write) sobre o **Service Control Manager (svcctl)**, a interface responsável pela gestão de serviços no Windows. Esse comportamento, ocorrendo milissegundos após o acesso ao IPC$, é um indicador crítico da técnica de **Service Execution**, onde o adversário utiliza o pipe de comunicação para injetar e iniciar serviços maliciosos com privilégios de `SYSTEM`.

<img width="1920" height="912" alt="image" src="https://github.com/user-attachments/assets/5e5a6f9c-d1e7-4e95-a3c2-e3f56e94f090" />

### Ato VIII: Abuso de Privilégios Sensíveis e Domínio do Sistema (SeTakeOwnershipPrivilege)

A investigação culminou na detecção do uso de direitos especiais através da query `event.provider:"Microsoft-Windows-Security-Auditing" and winlog.event_id:"4674" and user.name:"system_admin"`, monitorando o acesso a objetos privilegiados. O usuário comprometido exerceu o privilégio de **Apropriação de Objeto (Take Ownership)** sobre o **SC Manager (ServicesActive)**, garantindo a capacidade de ignorar quaisquer restrições de segurança existentes no banco de dados de serviços do Windows. 

Este comportamento, ocorrendo em sincronia com o acesso ao pipe `svcctl`, é a evidência definitiva de que o adversário obteve permissão para "sobrescrever" a autoridade do sistema, permitindo a instalação de backdoors ou a desativação de agentes de segurança (EDR/Antivírus).

<img width="1914" height="925" alt="image" src="https://github.com/user-attachments/assets/ab8f78db-ce4a-49d7-ba50-cd8c7d4c766a" />

### Indicadores de Comprometimento (IoCs)

- IP Atacante: 172.16.98.100
- Contas Comprometidas: helpdesk1, system_admin
- Pipes Alvos: \pipe\svcctl

### Conclusão e Análise Forense 🏁

A correlação dos logs revelou uma progressão de ataque extremamente ágil e coordenada, que levou o adversário do reconhecimento inicial ao domínio total do servidor em menos de cinco minutos. Através da análise técnica, foi possível mapear a transição crítica entre o **Acesso Inicial** (via *Password Spraying*) e a **Persistência de Domínio** (via manipulação de ACLs no Active Directory e abuso do pipe `svcctl`). A detecção do privilégio `SeTakeOwnershipPrivilege` em conjunto com a modificação do atributo `nTSecurityDescriptor` confirma que o atacante não buscava apenas um acesso temporário, mas sim a criação de *backdoors* estruturais que permitiriam o retorno ao ambiente mesmo após a rotação de credenciais administrativas, caracterizando um comprometimento severo da integridade do Active Directory.

Como medidas de segurança e remediação, é imperativo implementar o **Princípio do Privilégio Mínimo (PoLP)**, restringindo o uso de contas como `system_admin` apenas a estações de gerenciamento seguro (PAWs) e desativando privilégios sensíveis para usuários que não necessitam de gestão de serviços. Além disso, recomenda-se a configuração de alertas em tempo real no SIEM para os Event IDs **5136** (mudanças de ACL) e **4674** (uso de privilégios de apropriação), além da aplicação de **MFA (Autenticação de Múltiplos Fatores)** em todos os níveis de acesso remoto. Para este incidente específico, a recuperação exige o isolamento imediato do Controlador de Domínio, a restauração das permissões originais dos objetos do AD via backup íntegro e a execução de um processo de *eviction* total para eliminar possíveis binários de persistência injetados via `svcctl`.








