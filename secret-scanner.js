/**
 * Katana Secret Scanner - Deep Credential & Token Detection Engine
 * Scans HTML, Rendered DOM, External JS Bundles, CSS, and Source Maps (.js.map)
 * Powered by 420+ curated rules from regax.txt with noise filtering & entropy validation.
 */

const KATANA_SECRET_RULES = {
  "Slack Token": "xox[pboa]-[0-9]{12}-[0-9]{12}-[0-9]{12}-[a-z0-9]{32}",
  "Google API Key": "AIza[0-9A-Za-z\\-_]{35}",
  "RSA private key": "-----BEGIN RSA PRIVATE KEY-----",
  "SSH (DSA) private key": "-----BEGIN DSA PRIVATE KEY-----",
  "SSH (EC) private key": "-----BEGIN EC PRIVATE KEY-----",
  "PGP private key block": "-----BEGIN PGP PRIVATE KEY BLOCK-----",
  "Amazon MWS Auth Token": "amzn\\.mws\\.[0-9a-f\\-]{36}",
  "AWS AppSync GraphQL Key": "da2-[a-z0-9]{26}",
  "Facebook Access Token": "EAACEdEose0cBA[0-9A-Za-z]+",
  "GitHub Token": "[gG][iI][tT][hH][uU][bB].{0,20}['|\"][0-9a-zA-Z]{35,40}['|\"]",
  "Google Service Account": "\"type\":\\s*\"service_account\"",
  "Heroku API Key": "[hH][eE][rR][oO][kK][uU].{0,20}[0-9A-Fa-f\\-]{36}",
  "JWT": "eyJhbGciOiJ[a-zA-Z0-9_-]{5,}\\.[a-zA-Z0-9_-]+\\.[a-zA-Z0-9_-]+",
  "MailChimp API Key": "[0-9a-f]{32}-us[0-9]{1,2}",
  "Slack Webhook": "https://hooks\\.slack\\.com/services/[A-Za-z0-9_/]{24,}",
  "Stripe Key": "(sk|rk)_live_[0-9a-zA-Z]{24}",
  "Telegram Bot Token": "[0-9]+:AA[0-9A-Za-z\\-_]{33}",
  "Twilio API Key": "SK[0-9a-fA-F]{32}",
  "Generic API Key": "[aA][pP][iI]_?[kK][eE][yY].{0,20}['|\"][0-9a-zA-Z]{32,45}['|\"]",
  "Generic Secret": "[sS][eE][cC][rR][eE][tT].{0,20}['|\"][0-9a-zA-Z]{32,45}['|\"]",
  "Adafruit IO Key": "\\b(aio_[a-zA-Z]{4}[0-9]{2}[a-zA-Z0-9]{22})\\b",
  "Adobe Stock API Key": "\\badobe(?:.|[\\n\\r]){0,32}?\\b([A-F0-9]{32})\\b",
  "Adobe IO Product ID": "\\badobe(?:.|[\\n\\r]){0,64}?\\b([a-z0-9]{12})\\b",
  "Adobe OAuth Client Secret": "\\b(p8e-[A-Z0-9-]{32})(?:[^A-Z0-9-])",
  "Age Recipient (X25519 public key)": "(age1[0-9a-z]{58})\\b",
  "Age Identity (X22519 secret key)": "(AGE-SECRET-KEY-1[0-9A-Z]{58})",
  "AI21 Studio API Key": "\\bai21(?:.|[\\n\\r]){0,32}?\\b([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})\\b",
  "Airbrake User Key": "\\bairbrake(?:.|[\\n\\r]){0,32}?([A-Z0-9-]{40})\\b",
  "Airtable Personal Access Token": "\\b(pat[a-z0-9]{14}\\.[a-z0-9]{62,66})\\b",
  "Airtable OAuth Token": "([A-Z0-9]+\\.v1\\.[A-Z0-9_-]+\\.[a-f0-9]+)\\b",
  "Aiven API Key": "aiven(?:.|[\\n\\r]){0,32}?\\b([a-z0-9/+=]{372})(?:[^A-Za-z0-9/+=])",
  "Algolia Admin API Key": "algolia(?:.|[\\n\\r]){0,32}?([a-z0-9]{32})\\b",
  "Algolia Application ID": "algolia(?:.|[\\n\\r]){0,16}?([A-Z0-9]{10})\\b",
  "Alibaba Access Key ID": "(LTAI[a-z0-9]{17,21})\\b",
  "Alibaba Access Key Secret": "\\balibaba(?:.|[\\n\\r]){0,32}?([a-z0-9]{30})",
  "Anthropic API Key": "\\b(sk-ant-[A-Za-z0-9_-]{20,200})\\b",
  "Anypoint API Key": "anypoint(?:.|[\\n\\r]){0,32}?(?:SECRET|PRIVATE|ACCESS|KEY|TOKEN)(?:.|[\\n\\r]){0,32}?\\b([0-9a-z]{8}-[0-9a-z]{4}-[0-9a-z]{4}-[0-9a-z]{4}-[0-9a-z]{12})\\b",
  "Apify API Token": "(apify_api_[A-Z0-9]{34,38})\\b",
  "Artifactory Access Token": "\\b(AKC[A-Z0-9]{64,74})\\b",
  "Artifactory JFrog URL": "\\b([a-z0-9](?:[a-z0-9\\-]{0,61}[a-z0-9])?\\.jfrog\\.io)\\b",
  "Asana Client ID": "\\basana(?:.|[\\n\\r]){0,32}?\\b([0-9]{16})\\b",
  "Asana Client Secret": "\\basana(?:.|[\\n\\r]){0,64}?\\b([a-z0-9]{30,40})\\b",
  "Asana OAuth / Personal Access Token": "\\basana(?:.|[\\n\\r]){0,64}?\\b([01]{1,}\\/[0-9a-f]{16,32}(?::[a-z0-9]{32,64})?)\\b",
  "AssemblyAI API Key": "\\bassemblyai(?:.|[\\n\\r]){0,32}?\\b([0-9a-z]{32})\\b",
  "Atlassian API token": "\\batlassian(?:.|[\\n\\r]){0,32}?\\b([a-z0-9]{24})\\b",
  "Atlassian Admin API Key": "(?:atlassian|api\\.atlassian\\.com)(?:.|[\\n\\r]){0,128}?\\b(AT[A-Za-z0-9_\\-=]{60,260})\\b",
  "Auth0 Client ID": "\\bauth0(?:.|[\\n\\r]){0,32}?\\b([a-z0-9_-]{32,60})\\b",
  "Auth0 Client Secret": "\\bauth0(?:.|[\\n\\r]){0,16}?(?:SECRET|PRIVATE|ACCESS|KEY|TOKEN)(?:.|[\\n\\r]){0,64}?\\b([a-z0-9_-]{64,})\\b",
  "Auth0 Domain": "\\b([a-z0-9][a-z0-9._-]*auth0\\.com)\\b",
  "Authress Service Client Access Key": "((?:sc|ext|scauth|authress)_[a-z0-9]{5,30}\\.[a-z0-9]{4,6}\\.acc[_-][a-z0-9-]{10,32}\\.[a-z0-9+/_=-]{30,120})\\b",
  "AWS Access Key ID": "\\b((?:A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[2-7A-Z]{16})\\b",
  "AWS Secret Access Key": "(?:\\b(?:AWS|AMAZON|AMZN|A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)(?:.|[\\n\\r]){0,64}?[^A-Za-z0-9_+!@\\#$%^&*()\\]./]([A-Za-z0-9/+]{40})[^A-Za-z0-9_+!@\\#$%^&*()\\]./]|\\b(?:AWS|AMAZON|AMZN|A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)(?:.|[\\n\\r]){0,96}?(?:SECRET|PRIVATE|ACCESS)(?:.|[\\n\\r]){0,16}?(?:KEY|TOKEN)(?:.|[\\n\\r]){0,64}?\\b([A-Za-z0-9/+]{40})\\b)",
  "AWS Bedrock API Key (Long-lived)": "(ABSKQmVkcm9ja0FQSUtleS[A-Za-z0-9+/=]{110})",
  "AWS Bedrock API Key (Short-lived)": "(bedrock-api-key-YmVkcm9jay5hbWF6b25hd3MuY29t[A-Za-z0-9+/]+={0,2})",
  "Azure Connection String": "(?:AccountName|SharedAccessKeyName|SharedSecretIssuer)\\s*=\\s*([^;]{1,80})\\s*;\\s*.{0,10}\\s*(?:AccountKey|SharedAccessKey|SharedSecretValue)\\s*=\\s*([^;]{1,100})(?:;|$)",
  "Azure App Configuration Connection String": "(https://[A-Z0-9-]+\\.azconfig\\.io);Id=(.{4}-.{2}-.{2}:[A-Z0-9+/]{18,22});Secret=([A-Z0-9+/]{36,50}=)",
  "Azure Personal Access Token": "(?i:ADO_PAT|pat_token|personal_?access_?token|\\$token)\\s*=\\s*[\"']([a-z0-9]{52})[\"']",
  "Azure Container Registry URL": "([a-z0-9][a-z0-9-]{1,100}[a-z0-9])\\.azurecr\\.io",
  "Azure Container Registry Password": "\\b([A-Z0-9+/]{42}\\+ACR[A-Z0-9]{6})\\b",
  "Azure DevOps Organization": "\\bdev\\.azure\\.com/([a-z0-9][a-z0-9-]{0,61}[a-z0-9])",
  "Azure DevOps Personal Access Token": "\\b([a-z0-9]{76}AZDO[a-z0-9]{4,5})\\b",
  "Azure OpenAI API Key": "\\bazure(?:.|[\\n\\r]){0,8}?(?:openai)(?:.|[\\n\\r]){0,16}?(?:SECRET|PRIVATE|ACCESS|KEY|TOKEN)(?:.|[\\n\\r]){0,8}?([a-f0-9]{32})\\b",
  "Azure OpenAI Host": "\\b([a-z0-9-]{3,32}\\.openai\\.azure\\.com)\\b",
  "Azure Search Query Key": "\\bazure(?:.|[\\n\\r]){0,32}?(?:SECRET|PRIVATE|ACCESS|KEY|TOKEN)(?:.|[\\n\\r]){0,32}?([0-9A-Z]{52})\\b",
  "Azure Search URL": "\\bazure(?:.|[\\n\\r]){0,32}?https:\\/\\/([0-9a-z]{5,40}\\.search\\.windows\\.net\\/indexes\\/[0-9a-z]{5,40})\\b",
  "Azure Storage Account Name": "(?:(?i:AccountName)\\s*=\\s*([a-z0-9]{3,24})(?:\\b|[^a-z0-9])|([a-z0-9]{3,24})\\.blob\\.core\\.windows\\.net\\b|\\bazure(?:[_\\s-]*)(?:storage|account)(?:[_\\s-]*)(?:name)\\b[\\s:=\\\"']{0,6}([a-z0-9]{3,24})(?:\\b|[^a-z0-9]))",
  "Azure Storage Account Key": "\\bazure(?:.|[\\n\\r]){0,128}?(?:SECRET|PRIVATE|ACCESS|KEY|TOKEN)(?:.|[\\n\\r]){0,128}?[\"':\\s=}\\]\\)]((?:[A-Z0-9+\\-]{86,88}={1,2})|(?:[A-Z0-9+\\-]{86,88}\\b))",
  "Baremetrics API Key": "\\bbaremetrics(?:.|[\\n\\r]){0,32}?\\b([a-z0-9_-]{25})\\b",
  "Baseten API Key": "\\bbaseten(?:.|[\\n\\r]){0,32}?\\b([A-Za-z0-9]{8}\\.[A-Za-z0-9]{32})\\b",
  "Beamer API token": "\\bbeamer(?:.|[\\n\\r]){0,64}?\\b(b_[A-Z0-9=_\\\\/\\\\\\-+]{44})\\b",
  "Bitbucket Client ID": "\\bbitbucket(?:.|[\\n\\r]){0,16}?(?:client|id)(?:.|[\\n\\r]){0,16}?([a-z0-9]{30,40})\\b",
  "Bitbucket Secret": "\\bbitbucket(?:.|[\\n\\r]){0,32}?(?:SECRET|PRIVATE|ACCESS|KEY|TOKEN)(?:.|[\\n\\r]){0,32}?\\b([a-z0-9+_\\-+]{44})\\b",
  "Bitly Access Token": "\\bbitly(?:.|[\\n\\r]){0,32}?(?:SECRET|PRIVATE|ACCESS|KEY|TOKEN)(?:.|[\\n\\r]){0,32}?([a-f0-9]{40})\\b",
  "Blynk Device Access Token": "https://(?:fra1\\.|lon1\\.|ny3\\.|sgp1\\.|blr1\\.)*blynk\\.cloud/external/api/[A-Z0-9/]*\\?token=([A-Z0-9_\\-]{32})&",
  "Blynk Organization Access Token": "https://(?:fra1\\.|lon1\\.|ny3\\.|sgp1\\.|blr1\\.)*blynk\\.cloud/api/[A-Z0-9_\\-\\s/\\\\]*-H\\s*\"Authorization:\\s*Bearer\\s*([A-Z0-9_\\-]{40})\"",
  "Blynk Organization Client Credentials": "https://(?:fra1\\.|lon1\\.|ny3\\.|sgp1\\.|blr1\\.)*blynk\\.cloud/oauth2/[A-Z0-9_\\-\\s/\\\\?=&]*(oa2-client-id_[A-Z0-9_\\-]{32})(?::|&client_secret=)([A-Z0-9_\\-]{40})",
  "Buildkite API Key": "(bkua_[a-z0-9]{40})\\b",
  "Cerebras AI API Key": "(csk-[a-z0-9]{48})\\b",
  "CircleCI API Personal Access Token": "\\b(CCIPAT_[a-z0-9]{4}[a-z]{5}[a-z0-9]{3}[0-9]{3}[a-z]{2}[A-Z]{2}[0-9]{1}[a-z]{1}[a-z0-9]{1}[0-9]{1}[a-z]{1}_[a-z0-9]{40})\\b",
  "CircleCI API Project Token": "\\bcircleci(?:.|[\\n\\r]){0,64}?([a-f0-9]{40})\\b",
  "Cisco Meraki API Key": "meraki(?:.|[\\n\\r]){0,32}?([0-9a-f]{40})\\b",
  "Clarifai API Key": "\\bclarifai(?:.|[\\n\\r]){0,32}?\\b([0-9a-f]{32,36})\\b",
  "Clearbit API Key": "\\bclearbit(?:.|[\\n\\r]){0,16}?(?:SECRET|PRIVATE|ACCESS|KEY|TOKEN)(?:.|[\\n\\r]){0,32}?\\b([0-9a-z_]{35})\\b",
  "ClickHouse Cloud Secret Key": "\\b(4b1d[a-z0-9]{38})\\b",
  "ClickHouse Cloud Key ID": "\\bclickhouse(?:.|[\\n\\r]){0,16}?(?:ID|USER)(?:.|[\\n\\r]){0,16}?([a-z0-9]{20})",
  "Clojars Username": "\\bclojars(?:.|[\\n\\r]){0,32}?(?:ID|USER)(?:.|[\\n\\r]){0,16}?\\b([a-z0-9_-]{3,})\\b",
  "Clojars API Token": "\\b(CLOJARS_[a-z0-9]{60})\\b",
  "Cloudflare API Token": "\\bcloudflare(?:.|[\\n\\r]){0,32}?(?:SECRET|PRIVATE|ACCESS|KEY|TOKEN)(?:.|[\\n\\r]){0,32}?\\b([a-z0-9_-]{38,42})\\b",
  "Cloudflare CA Key": "\\b(?:cloudflare|x-auth-user-service-key)(?:.|[\\n\\r]){0,64}?(v1\\.0-[a-z0-9._-]{160,})\\b",
  "CloudSight API Key": "\\bcloudsight(?:.|[\\n\\r]){0,32}?(?:SECRET|PRIVATE|ACCESS|KEY|TOKEN)(?:.|[\\n\\r]){0,32}?\\b([a-z0-9]{20,24})\\b",
  "Codacy API Key": "\\bcodacy(?:.|[\\n\\r]){0,32}?(?:SECRET|PRIVATE|ACCESS|KEY|TOKEN)(?:.|[\\n\\r]){0,32}?\\b([0-9A-Z]{20,24})\\b",
  "CodeClimate Reporter ID": "(?:CODECLIMATE|CC_TEST_REPORTER_ID)(?:.|[\\n\\r]){0,64}?\\b([a-f0-9]{64})\\b",
  "Codecov Access Token": "\\bcodecov(?:.|[\\n\\r]){0,32}?(?:SECRET|PRIVATE|ACCESS|KEY|TOKEN)(?:.|[\\n\\r]){0,32}?\\b([A-Z0-9-]{36})\\b",
  "Cohere API Key": "\\bcohere(?:.|[\\n\\r]){0,16}?\\b([A-Z0-9]{40})\\b",
  "Coinbase Access Token": "\\bcoinbase(?:.|[\\n\\r]){0,16}?(?:SECRET|PRIVATE|ACCESS|KEY|TOKEN)(?:.|[\\n\\r]){0,16}?\\b([a-z-0-9]{32})\\b",
  "Coinbase CDP API Key (ECDSA)": "\"name\"\\s*:\\s*\"(organizations/[0-9a-f-]{36}/apiKeys/[0-9a-f-]{36})\".*\"privateKey\"\\s*:\\s*\"(-----BEGIN\\sEC\\s{0,1}PRIVATE\\sKEY(\\sBLOCK)?-----[a-z0-9 /+=\\r\\n\\\\n]{32,}?-----END\\s(?:RSA|PGP|DSA|OPENSSH|ENCRYPTED|EC)?\\s{0,1}PRIVATE\\sKEY(\\sBLOCK)?-----)",
  "Coinbase CDP API Key (Ed25519)": "\"id\"\\s*:\\s*\"([0-9a-f-]{36})\"[^{]*?\"privateKey\"\\s*:\\s*\"([A-Za-z0-9+/=]{88})\"",
  "Confluent Client ID": "\\b(?:confluent|ccloud|cpdev|kafka)(?:.|[\\n\\r]){0,32}?\\b([A-Z0-9]{16})\\b",
  "Confluent API Secret": "(?:confluent|ccloud|cpdev|kafka)(?:.|[\\n\\r]){0,32}?(?:SECRET|PRIVATE|ACCESS|KEY|TOKEN)(?:.|[\\n\\r]){0,32}?\\b([A-Z0-9\\+/]{64})",
  "Confluent API Secret - Updated Format": "\\b(cflt([A-Za-z0-9\\+/]{54})([A-Za-z0-9\\+/]{6}))",
  "Contentful Delivery API Token": "\\bcontentful(?:.|[\\n\\r]){0,32}?(?:SECRET|PRIVATE|ACCESS|KEY|TOKEN)(?:.|[\\n\\r]){0,32}?\\b([A-Z0-9_-]{43,45})\\b",
  "Contentful Personal Access Token": "(CFPAT-[A-Z0-9_-]{43})",
  "Coze Personal Access Token": "coze(?:.|[\\n\\r]){0,32}?\\b(pat_[A-Z0-9]{64})\\b",
  "crates.io API Key": "\\b(cio[A-Z0-9]{32})\\b",
  "Credentials in a URL": "https?:\\/\\/([a-z0-9._~-]+):([a-z0-9._~-]+)@([a-z0-9.-]+)(\\/[a-z0-9\\/._~-]*)?",
  "Databricks API token": "\\b(dapi[a-f0-9]{32})\\b",
  "Databricks API Token": "\\b(dapi[0-9a-f]{32})(-\\d)?\\b",
  "Databricks Domain": "\\b([a-z0-9-]+(?:\\.[a-z0-9\\-]+)*\\.(cloud\\.databricks\\.com|gcp\\.databricks\\.com|azurewebsites\\.net))\\b",
  "Datadog API Key": "\\b(?:datadog|dd)(?:.|[\\n\\r]){0,64}?(?:SECRET|PRIVATE|ACCESS|KEY|TOKEN)(?:.|[\\n\\r]){0,32}?\\b([A-Za-z0-9]{32})\\b",
  "Deepgram API Key": "\\bdeepgram(?:.|[\\n\\r]){0,32}?\\b([0-9a-f]{40})\\b",
  "DeepSeek API Key": "\\b(sk-[a-f0-9]{32})\\b",
  "Dependency-Track API Key": "\\b(odt_[A-Z0-9]{32,255})\\b",
  "Diffbot API Key": "\\bdiffbot(?:.|[\\n\\r]){0,32}?\\b([0-9a-z]{32})\\b",
  "DigitalOcean API Key": "\\b((?:dop|doo)_v1_[a-f0-9]{64})\\b",
  "DigitalOcean Refresh Token": "(dor_v1_[a-f0-9]{64})",
  "Discord Webhook URL": "(https://discord\\.com/api/webhooks/\\d{18})/([0-9a-z_\\-]{68})\\b",
  "Discord Bot Token": "([MNO][A-Z0-9_-]{23}\\.[A-Z0-9_-]{6}\\.[A-Z0-9_-]{27})\\b",
  "Discord Bot ID": "(?:discord|botid|bot_id)(?:.|[\\n\\r]){0,64}?(\\d{17,19})",
  "Django Secret Key": "[DJANGO]\\w{0,8}SECRET_KEY.{1,16}?([A-Za-z0-9*!$@\\#&_%^-]{45,55})\\b",
  "Docker Registry Credentials (auths JSON)": "\"auths\"\\s*:\\s*\\{[^}]*?\"((?:https?:\\/\\/)?[a-z0-9.\\-:+/]+)\"\\s*:\\s*\\{[^}]*?\"auth\"\\s*:\\s*\"([A-Za-z0-9+/=]{16,})\"[^}]*?\\}[^}]*?\\}",
  "Docker Hub Personal Access Token": "\\b(dckr_pat_[A-Z0-9_-]{27})(?:$|[^A-Z0-9_-])",
  "Doppler CLI Token": "\\b(dp\\.ct\\.[A-Z0-9]{40,44})\\b",
  "Doppler Personal Token": "\\b(dp\\.pt\\.[A-Z0-9]{40,44})\\b",
  "Doppler Service Token": "\\b(dp\\.st\\.(?:[a-z0-9\\-_]{2,35}\\.)?[A-Z0-9]{40,44})\\b",
  "Doppler Service Account Token": "\\b(dp\\.sa\\.[A-Z0-9]{40,44})\\b",
  "Doppler SCIM Token": "\\b(dp\\.scim\\.[A-Z0-9]{40,44})\\b",
  "Doppler Audit Token": "\\b(dp\\.audit\\.[A-Z0-9]{40,44})\\b",
  "DroneCI Access Token": "\\b(?:drone|droneci|drone[_-])(?:.|[\\n\\r]){0,16}?(?:SECRET|PRIVATE|ACCESS|KEY|TOKEN)(?:.|[\\n\\r]){0,16}?\\b(ey[A-Za-z0-9_-]{30,}\\.[A-Za-z0-9_-]{10,}\\.[A-Za-z0-9_-]{10,}|[a-f0-9]{32,64})\\b",
  "Dropbox API secret/key": "\\b(sl\\.[A-Z0-9\\-\\_]{130,152})\\b",
  "Duffel API Token": "\\b(duffel_(?:test|live)_[a-z0-9_\\-=]{43})\\b",
  "Dynatrace Token": "\\b(dt0[a-z][0-9]{2}\\.[A-Z0-9]{24}\\.[A-Z0-9]{64})\\b",
  "EasyPost API token": "\\b(EZ[AT]K[A-Za-z0-9]{54})\\b",
  "ElevenLabs API Key": "\\b(sk_[0-9a-f]{48})\\b",
  "Eraser API Key": "\\beraser(?:[^A-Za-z0-9]{0,16})?(?:SECRET|PRIVATE|ACCESS|KEY|TOKEN)(?:[^A-Za-z0-9]{0,16})?\\b([A-Za-z0-9]{20})\\b",
  "Facebook App ID": "\\b(?:facebook|fb)(?:.|[\\n\\r]){0,8}?(?:APP|APPLICATION)(?:.|[\\n\\r]){0,16}?\\b(\\d{15})\\b",
  "Facebook Secret Key": "\\b(?:facebook|fb).?(?:api|app|application|client|consumer|customer|secret|key).?(?:key|oauth|sec|secret)?.{0,2}\\s{0,20}.{0,2}\\s{0,20}.{0,2}\\b([a-z0-9]{32})\\b",
  "Fastly API token": "\\bfastly(?:.|[\\n\\r]){0,32}?(?:SECRET|PRIVATE|ACCESS|KEY|TOKEN)(?:.|[\\n\\r]){0,32}?\\b([a-z0-9_-]{32})\\b",
  "Figma Personal Access Token": "\\b(figd_[A-Z0-9_-]{38,42})\\b",
  "Figma Personal Access Header Token": "figma(?:.|[\\n\\r]){0,32}?([0-9A-F]{4}-[0-9A-F]{8}(?:-[0-9A-F]{4}){3}-[0-9A-F]{12})",
  "FileIO Secret Key": "\\bfileio(?:.|[\\n\\r]){0,32}?(?:SECRET|PRIVATE|ACCESS|KEY|TOKEN)(?:.|[\\n\\r]){0,16}?\\b([A-Z0-9]{20}\\.[A-Z0-9]{20})\\b",
  "Finicity API token": "\\bfinicity(?:.|[\\n\\r]){0,32}?(?:SECRET|PRIVATE|ACCESS|KEY|TOKEN)(?:.|[\\n\\r]){0,32}?\\b([a-f0-9]{32})\\b",
  "Finicity client secret": "\\bfinicity(?:.|[\\n\\r]){0,64}?\\b([a-z0-9]{20})\\b",
  "Finnhub API Token": "\\bfinnhub(?:.|[\\n\\r]){0,24}?\\b([a-z0-9]{20})\\b",
  "Firecrawl API Key": "\\b(fc-[a-f0-9]{32})\\b",
  "Fireworks.ai API Key": "\\b(fw_[A-Z0-9]{24})\\b",
  "Flickr API Key": "\\bflickr(?:.|[\\n\\r]){0,16}?(?:SECRET|PRIVATE|ACCESS|KEY|TOKEN)(?:.|[\\n\\r]){0,32}?\\b([a-f0-9]{32})\\b",
  "Flickr OAuth Token": "\\bflickr(?:.|[\\n\\r]){0,32}?(?:OAUTH|ACCESS|TOKEN)?(?:.|[\\n\\r]){0,32}?([a-f0-9]{32})",
  "Fly.io API Token": "\\b(FlyV1\\s[A-Za-z0-9=_\\-,/+]{100,})\\b",
  "Frame.io API token": "\\b(fio-u-(?:[A-Z0-9_-]{16}){4})\\b",
  "Frame.io API Token": "\\b(fio-u-[a-z0-9\\-_=]{64})\\b",
  "FreshBooks Access Token": "\\bfreshbooks(?:.|[\\n\\r]){0,32}?\\b([a-z0-9]{64})\\b",
  "Friendli.ai API Key": "\\b(flp_[A-Z0-9]{46})\\b",
  "GCP API Token": "(\\{[^{}]*\\\"auth_provider_x509_cert_url\\\":.{0,512}?})|\\{(?:[^{}]|\\{(?:[^{}]|\\{[^{}]*\\})*\\})*\"auth_provider_x509_cert_url\":\\s*\".+?\"(?:[^{}]|\\{(?:[^{}]|\\{[^{}]*\\})*\\})*\\}",
  "GCP Private Key ID": "\\bgcp(?:.{0,20}?(?:key|secret)).{0,12}[=:]\\s{0,8}[\"']?([0-9a-z]{35,40})[\"']?\\b",
  "Generic Username and Password": "(?:username|user)(?:.|[\\n\\r]){0,16}?(?:password|pass)(?:.|[\\n\\r]){0,16}?[\"']([^\"']{5,30})[\"']",
  "Generic Password": "password(?:.|[\\n\\r]){0,16}?[\"']([^$<%@.,\\s'\"(){}&/#\\-][^\\s'\"(){}/]{4,})[\"']",
  "Weak Password Pattern": "(blink\\d{3,6}|correcthorsebatterystaple\\d{0,6}|letmein\\d{1,6}|newpass\\d{1,6}|p@ssw0rd\\d{0,6}|pa55word\\d{0,6}|pass4now\\d{0,6}|password\\d{1,6}|qwer\\d{4,6}|qwerty\\d{3,6}|trustno\\d{1,6})",
  "Docker Robot Credentials (plaintext pair)": "(([a-z0-9._-]+\\+[a-z0-9._-]+):([A-Z0-9]{32,80}))\\b",
  "Gitalk OAuth Credentials": "\\bnew\\s+Gitalk\\s*\\(\\s*\\{\\s*clientID:\\s*'([a-f0-9]{20})',\\s*clientSecret:\\s*'([a-f0-9]{40})',",
  "GitHub Personal Access Token - fine-grained permissions": "(github_pat_[A-Z0-9_+]{82,84})\\b",
  "GitHub Personal Access Token": "(ghp_([A-Z0-9]{30})([A-Z0-9]{6}))",
  "GitHub OAuth Access Token": "(gho_([A-Z0-9]{30})([A-Z0-9]{6}))",
  "GitHub App User-to-Server Token": "(ghu_([A-Z0-9]{30})([A-Z0-9]{6}))",
  "GitHub App Server-to-Server Token": "(ghs_([A-Z0-9]{30})([A-Z0-9]{6}))",
  "GitHub Refresh Token": "(ghr_([A-Z0-9]{30})([A-Z0-9]{6}))",
  "GitHub Client ID": "(?:github).?(?:api|app|application|client|consumer|customer)?.?(?:id|identifier|key).{0,2}\\s{0,20}.{0,2}\\s{0,20}.{0,2}\\b([a-z0-9]{20})\\b",
  "GitHub Secret Key": "github(?:.|[\\n\\r]){0,32}?(?:SECRET|PRIVATE|ACCESS|KEY|TOKEN)(?:.|[\\n\\r]){0,32}?\\b([a-z0-9]{40})\\b",
  "GitLab Private Token": "\\b(glpat-[0-9A-Z_-]{20})\\b",
  "GitLab Runner Registration Token": "\\b(GR1348941[0-9A-Z_-]{20})\\b",
  "GitLab Pipeline Trigger Token": "\\b(glptt-[0-9a-f]{40})",
  "GitLab Private Token - Routable Format": "\\b(glpat-(?<base64_payload>[0-9A-Za-z_-]{27,300})\\.(?<version>01)\\.(?<base36_payload_length>[0-9a-z]{2})(?<crc32>[0-9a-z]{7}))\\b",
  "Gitter Access Token": "\\bgitter(?:.|[\\n\\r]){0,24}?\\b([a-z0-9_-]{40})\\b",
  "GoCardless API Token": "\\bgocardless(?:.|[\\n\\r]){0,16}?\\b(live_[A-Z0-9=_-]{16}(?:[A-Z0-9=_-]{8}){3}[A-Z0-9=_-]{0,2})\\b",
  "Google OAuth Client Secret": "(GOCSPX-[A-Z0-9_-]{28})(?:[^A-Z0-9_-]|$)",
  "Google OAuth Access Token": "(ya29\\.[0-9A-Z_-]{20,1024})(?:[^0-9A-Z_-])",
  "Google OAuth Credentials": "([0-9]+-[a-z0-9_]{32}\\.apps\\.googleusercontent\\.com)(?:[\\s\\S]{0,40})(?:(GOCSPX-[A-Z0-9_-]{28})|(?:client.?secret.{0,10}\\b([A-Z0-9_-]{24})))(?:[^A-Z0-9_-]|$)",
  "Google Gemini API Key": "\\b(AIza[A-Za-z0-9_-]{35})\\b",
  "Google OAuth2 Access Token": "\\b(ya29\\.(?i:[a-z0-9_-]{30,}))\\b",
  "Hardcoded Gradle Credentials": "credentials\\s*\\{(?:\\s*//.*)*\\s*(?:username|password)\\s['\"]([^'\"]{1,60})['\"](?:\\s*//.*)*\\s*(?:username|password)\\s['\"]([^'\"]{1,60})['\"]",
  "Grafana API Token": "\\b(eyJrIjoi[a-z0-9]{60,100})\\b",
  "Grafana Cloud API Token": "\\b(glc_[a-z0-9+/]{40,150}={0,2})",
  "Grafana Service Account Token": "\\b(glsa_[A-Z0-9]{32}_[A-F0-9]{8})\\b",
  "Grafana Domain": "(?:https?://)?(?:[A-Z0-9-]+\\.){0,32}grafana\\.[A-Z0-9.-]{3,32}(?::\\d{2,5})?(?:[/?\\#]\\S*)?",
  "Groq API Key": "\\b(gsk_[a-zA-Z0-9]{52})\\b",
  "Password Hash (sha256crypt)": "(\\$5(?:\\$rounds=\\d+)?\\$[./A-Za-z0-9]{8,16}\\$[./A-Za-z0-9]{43})",
  "Password Hash (sha512crypt)": "(\\$6(?:\\$rounds=\\d+)?\\$[./A-Za-z0-9]{8,16}\\$[./A-Za-z0-9]{86})",
  "Password Hash (Cisco IOS PBKDF2 with SHA256)": "(\\$8\\$[./A-Za-z0-9]{8,16}\\$[./A-Za-z0-9]{43})",
  "Password Hash (Kerberos 5, etype 23, AS-REP)": "(\\$krb5asrep\\$23\\$(?:[^:]+:)?[0-9a-f]{32}\\$[0-9a-f]{64,})",
  "Hashicorp Vault Service Token (< v1.10)": "(?i:hashicorp|vault|token|key|secret)(?:.|[\\n\\r]){0,32}?\\b(s\\.[A-Za-z0-9_-]{24,128})\\b",
  "Hashicorp Vault Batch Token (< v1.10)": "(?i:hashicorp|vault|token|key|secret)[\"':=\\ ]{0,5}(b\\.[A-Za-z0-9_-]{24,500})(?:[^A-Za-z0-9_-]|$)",
  "Hashicorp Vault Recovery Token (< v1.10)": "(?i:hashicorp|vault|token|key|secret)[\"':=\\ ]{0,5}(r\\.[A-Za-z0-9_-]{24,500})(?:[^A-Za-z0-9_-]|$)",
  "Hashicorp Vault Service Token (>= v1.10)": "(hvs\\.[A-Za-z0-9]{24,130})(?:[^A-Za-z0-9_-]|$)",
  "Hashicorp Vault Batch Token (>= v1.10)": "(hvb\\.[A-Za-z0-9_-]{24,500})(?:[^A-Za-z0-9_-]|$)",
  "Hashicorp Vault Recovery Token (>= v1.10)": "(hvr\\.[A-Za-z0-9]{24,130})(?:[^A-Za-z0-9_-]|$)",
  "Hashicorp Vault Unseal Key": "(?i:unseal)\\b.{1,10}([a-zA-Z0-9+/]{44})(?:[^a-zA-Z0-9+/]|$)",
  "Heroku API Key (Platform Key)": "(HRKU-[A-Z0-9_]{60})",
  "HTTP Basic Authentication": "Authorization(?::\\s+|\\s*.{1,5}\\s*)Basic\\s+([A-Za-z0-9+/]{6,}={0,2})(?:[^A-Za-z0-9+/=]|$)",
  "HTTP Bearer Token": "Authorization(?::\\s+|\\s*.{1,5}\\s*)Bearer\\s+([A-Za-z0-9._~+/-]{6,}=*)(?:[^A-Za-z0-9._~+/=-]|$)",
  "HubSpot Private App Token": "\\b(pat-[a-z0-9]{2,3}-[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})\\b",
  "HuggingFace User Access Token": "(?:((?:api_org|hf)_(?:[0-9A-Z]{17}){2}))\\b",
  "IBM Cloud User API Key": "\\b(?:ibm(?:cloud)?|bx)(?:.|[\\n\\r]){0,32}?(?:SECRET|PRIVATE|ACCESS|KEY|TOKEN)(?:.|[\\n\\r]){0,32}?([0-9A-Z_-]{42,44})\\b",
  "Infracost API Token": "\\b(ico-[a-z0-9]{32})\\b",
  "Intercom API Token": "(?:intercom|ic)(?:.|[\\n\\r]){0,16}?(?:SECRET|PRIVATE|ACCESS|KEY|TOKEN)(?:.|[\\n\\r]){0,16}?\\b([0-9A-Z+/]{59}=)",
  "Ionic API token": "\\b(ion_[a-z0-9]{42})\\b",
  "IpStack API Key": "\\bipstack(?:.|[\\n\\r]){0,32}?(?:SECRET|PRIVATE|ACCESS|KEY|TOKEN)(?:.|[\\n\\r]){0,32}?\\b((?:[0-9a-f]{16}){2})\\b",
  "JDBC connection string with embedded credentials": "(jdbc:[a-z][a-z0-9+.-]{2,32}(?:[:][a-z0-9+.-]{1,32})*:[^\\s\"'<>,(){}\\[\\]]{10,448})",
  "Jina Search Foundation API Key": "\\b(jina_[a-zA-Z0-9]{60})\\b",
  "Jira Domain": "\\b([a-z][a-z0-9-]{5,24}\\.atlassian\\.net)\\b",
  "Jira Token": "\\bjira(?:.|[\\n\\r]){0,8}?(?:SECRET|PRIVATE|ACCESS|KEY|PASSWORD|TOKEN)(?:.|[\\n\\r]){0,16}?\\b([a-z0-9-]{24})\\b",
  "JSON Web Token (base64url-encoded)": "\\b(eyJ[A-Za-z0-9_-]{10,}\\.[A-Za-z0-9_-]{10,}\\.[A-Za-z0-9_-]{10,})\\b",
  "Kagi API Key": "(?:kagi)[\\s\\S]{0,100}([A-Za-z0-9_-]{11}\\.[A-Za-z0-9_-]{43})(?:$|[^A-Za-z0-9_-])",
  "Kickbox API Key": "\\bkickbox(?:.|[\\n\\r]){0,32}?(?:SECRET|PRIVATE|ACCESS|KEY|TOKEN)(?:.|[\\n\\r]){0,32}?\\b([A-Z0-9_]+[A-Z0-9]{64})\\b",
  "LangSmith Personal Access Token": "\\b(lsv2_(?:pt)_[0-9a-f]{32}_[0-9a-f]{10})\\b",
  "LangSmith Service Key": "\\b(lsv2_sk_[0-9a-f]{32}_[0-9a-f]{10})\\b",
  "LaunchDarkly Access Token": "launchdarkly(?:.|[\\n\\r]){0,32}?\\b([a-z0-9_\\-=]{40})",
  "Line Messaging API Token": "\\bline(?:.|[\\n\\r]){0,32}?(?:SECRET|PRIVATE|ACCESS|KEY|TOKEN)(?:.|[\\n\\r]){0,32}?\\b((?:[0-9A-Z+/]{57}){3}=?)",
  "Linear API Key": "\\b(lin_api_(?:[0-9A-Z]{8}){5})\\b",
  "LinkedIn Client ID": "linkedin.?(?:api|app|application|client|consumer|customer)?.?(?:id|identifier|key).{0,2}\\s{0,20}.{0,2}\\s{0,20}.{0,2}\\b([a-z0-9]{12,14})\\b",
  "LinkedIn Secret Key": "linkedin.?(?:api|app|application|client|consumer|customer|secret|key).?(?:key|oauth|sec|secret)?.{0,2}\\s{0,20}.{0,2}\\s{0,20}.{0,2}\\b([a-z0-9]{16})\\b",
  "Lob API Key": "lob(?:.|[\\n\\r]){0,24}?\\b((?:live|test)_[a-f0-9]{35})\\b",
  "Lob Publishable API Key": "lob(?:.|[\\n\\r]){0,24}?\\b((?:test|live)_pub_[a-f0-9]{31})\\b",
  "Mailchimp API Key": "\\bmailchimp(?:.|[\\n\\r]){0,128}?(?:SECRET|PRIVATE|ACCESS|KEY|TOKEN)(?:.|[\\n\\r]){0,32}?\\b((?:[0-9a-f]{8}){4}-us\\d{1,2})\\b",
  "MailGun Token": "\\bmailgun(?:.|[\\n\\r]){0,32}?(?:SECRET|PRIVATE|ACCESS|KEY|TOKEN)(?:.|[\\n\\r]){0,32}?\\b((?:[0-9A-Z-]{24}){3})",
  "MailGun Primary Key": "(?:mailgun|mg)(?:.|[\\n\\r]){0,64}?\\b(key-(?:[0-9a-f]{8}){4})\\b",
  "Mandrill API Key": "\\bmandrill(?:.|[\\n\\r]){0,32}?(?:SECRET|PRIVATE|ACCESS|KEY|TOKEN)(?:.|[\\n\\r]){0,32}?\\b((?:[0-9A-Z_-]{11}){2})",
  "Mapbox Secret Access Token": "mapbox[\\s\\S]{0,30}(sk\\.[a-z0-9\\-+/=]{32,128}\\.[a-z0-9\\-+/=]{20,30})\\b",
  "Mattermost URL": "\\bmattermost(?:.|[\\n\\r]){0,32}?(https?:\\/\\/[a-z0-9.-]+(?::\\d{2,5})?(?:\\/[A-Za-z0-9._~\\-\\/]*)?)\\b",
  "Mattermost Access Token": "\\bmattermost(?:.|[\\n\\r]){0,32}?(?:SECRET|PRIVATE|ACCESS|KEY|TOKEN)(?:.|[\\n\\r]){0,32}?\\b([A-Z0-9]{26})\\b",
  "MaxMind License Key": "\\b([a-z0-9]{6}_[a-z0-9]{29}_mmk)\\b",
  "MaxMind Account ID": "(?:maxmind|geoip|geolite)(?:.|[\\n\\r]){0,40}?(?:account|user)(?:.|[\\n\\r]){0,10}?(?:id|number)(?:.|[\\n\\r]){0,16}?(\\d{4,8})",
  "MessageBird API Token": "\\bmessage[_-]?bird(?:.|[\\n\\r]){0,32}?\\b([a-z0-9]{25})\\b",
  "Microsoft Teams Webhook": "\\b(https://[A-Z0-9]+\\.webhook\\.office\\.com/webhookb2/[A-Z0-9]{8}-[A-Z0-9]{4}-[A-Z0-9]{4}-[A-Z0-9]{4}-[A-Z0-9]{12}@[A-Z0-9]{8}-[A-Z0-9]{4}-[A-Z0-9]{4}-[A-Z0-9]{4}-[A-Z0-9]{12}/IncomingWebhook/[A-Z0-9]{32}/[A-Z0-9]{8}-[A-Z0-9]{4}-[A-Z0-9]{4}-[A-Z0-9]{4}-[A-Z0-9]{12})\\b",
  "Mistral AI API Key": "\\bmistral(?:.|[\\n\\r]){0,32}?(?:SECRET|PRIVATE|ACCESS|KEY|TOKEN)(?:.|[\\n\\r]){0,32}?\\b([A-Z0-9]{32})\\b",
  "Monday.com API Key": "\\bmonday(?:.|[\\n\\r]){0,40}?(?:SECRET|PRIVATE|ACCESS|KEY|TOKEN)(?:.|[\\n\\r]){0,40}?\\b(eyJ[A-Za-z0-9-_]{10,200}\\.eyJ[A-Za-z0-9-_]{50,1000}\\.[A-Za-z0-9-_]{20,500})\\b",
  "MongoDB API Private Key": "(?:(?:\\b|_|-|\\.)(?:mongodb|atlas)(?:\\b|_|-|\\.)).{0,1000}?(?:private|priv|secret|auth|pass|key)(?:.|[\\n\\r]){0,32}?\\b([a-fA-F0-9]{8}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{12})\\b",
  "MongoDB API PUBLIC Key": "(?:(?:\\b|_|-|\\.)(?:mongodb|atlas)(?:\\b|_|-|\\.))(?:public|pub|user|id)(?:.|[\\n\\r]){0,4}?([A-Z]+)(?:$|[^A-Z0-9/+=-])",
  "MongoDB URI Connection String": "\\b(mongodb(?:\\+srv)?://[\\S]{3,50}:(?:[\\S]{3,88})@[-.%\\w/:]+)\\b",
  "MongoDB Atlas Service Account Token": "\\b(mdb_sa_sk_[0-9A-Z_-]{6}[0-9A-Z]{34})",
  "MySQL URI with Credentials": "(mysql:\\/\\/(?:[a-z0-9._%+\\-]+):(?:[^\\s:@]+)@(?:\\[[0-9a-f:.]+\\]|[a-z0-9.-]+)(?::\\d{2,5})?(?:\\/[^\\s\"'?:]+)?(?:\\?[^\\s\"']*)?)",
  "NASA API Key": "\\bnasa\\.gov/.{0,200}(?:.|[\\n\\r]){0,32}?(?:SECRET|PRIVATE|ACCESS|KEY|TOKEN)(?:.|[\\n\\r]){0,32}?\\b([A-Z0-9]{40})\\b",
  "Netlify API Key": "netlify(?:.|[\\n\\r]){0,32}?(?:SECRET|PRIVATE|ACCESS|KEY|TOKEN)(?:.|[\\n\\r]){0,32}?\\b([a-f0-9]{60,64})\\b",
  "netrc Credentials": "(machine\\s+[^\\s]+|default)\\s+login\\s+([^\\s]+)\\s+password\\s+([^\\s]+)",
  "New Relic Personal API Key": "\\bnewrelic(?:.|[\\n\\r]){0,32}?(?:SECRET|PRIVATE|ACCESS|KEY|TOKEN)(?:.|[\\n\\r]){0,32}?\\b([A-Z0-9_.]{4}-[A-Z0-9_.]{42})\\b",
  "Ngrok API Key": "\\bngrok(?:.|[\\\\n\\r]){0,32}?(?:SECRET|PRIVATE|ACCESS|KEY|TOKEN)(?:.|[\\n\\r]){0,32}?((?:[a-z0-9]{25,30}_\\d[a-z0-9]{20}|(?:cr_|ak_)[a-z0-9]{25,30}))\\b",
  "Notion Legacy Token": "notion(?:.|[\\\\n\\r]){0,32}?\\b(secret_[A-Z0-9]{43})\\b",
  "Notion Token": "notion(?:.|[\\\\n\\r]){0,32}?(ntn_[A-Z0-9]{40,55})",
  "Notion OAuth Refresh Token": "notion(?:.|[\\\\n\\r]){0,32}?(nrt_[A-Z0-9_]{40,55})",
  "NPM Access Token (fine-grained)": "\\b(npm_([A-Za-z0-9]{30})([A-Za-z0-9]{6}))\\b",
  "NPM Access Token (old format)": "(?:_authToken|NPM_TOKEN)(?:.|[\\n\\r]){0,16}?([0-9A-F]{8}(?:-[0-9A-F]{4}){3}-[0-9A-F]{12})\\b",
  "NuGet API Key": "\\b(oy2[a-z0-9]{43})\\b",
  "NVIDIA NIM API Key": "(nvapi-[A-Z0-9_-]{60,70})\\b",
  "New York Times API Key": "(?:nytimes|new[- ]?york[- ]?times)(?:.|[\\n\\r]){0,32}?\\b([a-z0-9_\\-=]{32})\\b",
  "Credentials in ODBC Connection String": "(?:User|User\\ Id|UserId|Uid)\\s*=\\s*([^\\s;]{3,100})\\s*;[\\ \\t]*.{0,10}[\\ \\t]*(?:Password|Pwd)\\s*=\\s*([^\\t\\ ;]{3,100})\\s*(?:[;]|$)",
  "Okta API Token": "(?:okta|ssws)(?:.|[\\n\\r]){0,64}?\\b(00[a-z0-9_-]{39}[a-z0-9_])\\b",
  "Okta Domain": "([a-z0-9-]{1,40}\\.okta(?:preview|-emea)?\\.com)\\b",
  "Ollama API Key": "\\bollama(?:.|[\\n\\r]){0,32}?\\b([a-f0-9]{32}\\.[a-zA-Z0-9_-]{24})",
  "1Password Service-Account Token": "\\b(ops_eyj[A-Za-z0-9_-]{80,500})\\b",
  "1Password Account Secret Key": "(A[0-9]-[A-Z0-9]{6}-[A-Z0-9]{6}-[A-Z0-9]{5}(?:-[A-Z0-9]{5}){3})",
  "OpenAI API Key": "\\b(sk-(?:proj|live|test|svcacct)-[A-Za-z0-9_-]{20,200}|sk-[A-Za-z0-9]{48})\\b",
  "OpenWeather Map API Key": "(?:pyowm|openweather|\\bowm\\b)(?:.|[\\n\\r]){0,64}?\\b([a-z0-9]{32}|APPID=[a-z0-9]{32})\\b",
  "OpsGenie API Key": "\\bopsgenie(?:.|[\\\\n\\r]){0,32}?(?:SECRET|PRIVATE|ACCESS|KEY|TOKEN)(?:.|[\\n\\r]){0,32}?\\b([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})\\b",
  "PagerDuty API Key": "(?:pd[_-]?|pagerduty[_-]?|pagerduty)\\W{0,20}(?:SECRET|PRIVATE|ACCESS|KEY|TOKEN)(?:.|[\\n\\r]){0,16}?\\b(u\\+[A-Z0-9_+-]{18}|[A-Z0-9_-]{20}|[a-f0-9]{32})\\b",
  "particle.io Access Token": "https://api\\.particle\\.io/v1/[A-Z0-9_\\-\\s/\"\\\\?]*(?:access_token=|Authorization:\\s*Bearer\\s*)([A-Z0-9]{40})\\b",
  "Pastebin API Key": "\\bpastebin(?:.|[\\n\\r]){0,32}?(?:SECRET|PRIVATE|ACCESS|KEY|TOKEN)(?:.|[\\n\\r]){0,32}?\\b([A-Z0-9_]{32})\\b",
  "PayPal OAuth Client ID": "paypal(?:.|[\\n\\r]){0,8}?(?:CLIENT|ID|USER)(?:.|[\\n\\r]){0,16}?\\b(A[A-Z0-9_-]{78,99})",
  "PayPal OAuth Secret": "paypal(?:.|[\\n\\r]){0,16}?(?:SECRET|PRIVATE|ACCESS|KEY|TOKEN)(?:.|[\\n\\r]){0,32}?\\b([A-Z0-9_.-]{78,120})\\b",
  "PEM-Encoded Private Key": "-----BEGIN\\ .{0,20}\\ ?PRIVATE\\ KEY\\ ?.{0,20}-----\\s*((?:[a-zA-Z0-9+/=\\s\"',]|\\\\r|\\\\n){50,})\\s*-----END\\ .{0,20}\\ ?PRIVATE\\ KEY\\ ?.{0,20}-----",
  "Base64-PEM-Encoded Private Key": "((?:LS0tLS1CRUdJTi(?:BSU0EgUFJJVkFURSBLRVk|BEU0EgUFJJVkFURSBLRVk|BFQyBQUklWQVRFIEtFWQ|IFBSSVZBVEUgS0VZ)LS0tLS)[A-Za-z0-9+/=]{50,})(?:[^A-Za-z0-9+/=]|$)",
  "Perplexity AI API Key": "\\b(pplx-[A-Za-z0-9]{48})\\b",
  "PHPMailer Credentials": "\\$mail->Host\\s*=\\s*'([^'\\n]{5,})';\\s*(?://.*)?(?:\\s*.*\\s*){0,3}\\$mail->Username\\s*=\\s*'([^'\\n]{5,})';\\s*(?://.*)?(?:\\s*.*\\s*){0,3}\\$mail->Password\\s*=\\s*'([^'\\n]{5,})';",
  "PlanetScale API Token": "\\b(pscale_tkn_[a-z0-9-_]{43})\\b",
  "PlanetScale Username": "(?:pscale|planetscale)(?:.|[\\n\\r]){0,16}?(?:USER|ID|NAME)(?:.|[\\n\\r]){0,16}?([a-z0-9]{12})",
  "Postgres URL with hardcoded password": "(?:postgres(?:ql)?|postgis):\\/\\/(?:[\\w]+):(?:[^\\@]+)@(?:[^:\\/]+):(?:\\d+)",
  "PostHog Project API Key": "(phc_[a-zA-Z0-9_\\-]{43})",
  "PostHog Personal API Key": "(phx_[a-zA-Z0-9_\\-]{47})",
  "Postman API Key": "\\b(PMAK-[A-Z0-9]{24}-[A-Z0-9]{34})\\b",
  "Postmark API Token": "postmark[a-z0-9_-]{0,20}.{0,10}\\b([a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12})\\b",
  "Prefect API Token": "\\b(pnu_[a-z0-9]{36})\\b",
  "Contains encrypted RSA private key": "(-----BEGIN\\sRSA\\sPRIVATE\\sKEY(?:\\sBLOCK)?-----)[\\r\\n]Proc-Type:[\\s\\S]*?ENCRYPTED[\\r\\n]DEK-INFO[\\s\\S]*?[\\r\\n][\\r\\n][A-Za-z0-9/+=\\r\\n\\\\n]{32,}?-----END\\sRSA\\sPRIVATE\\sKEY(?:\\sBLOCK)?-----",
  "Contains Private Key": "(-----BEGIN\\s(?:RSA|PGP|DSA|OPENSSH|ENCRYPTED|EC)?\\s{0,1}PRIVATE\\sKEY(\\sBLOCK)?-----[a-z0-9 /+=\\r\\n\\\\n]{32,}?-----END\\s(?:RSA|PGP|DSA|OPENSSH|ENCRYPTED|EC)?\\s{0,1}PRIVATE\\sKEY(\\sBLOCK)?-----)",
  "Credentials in PsExec": "psexec.{0,100}-u\\s*(\\S+)\\s+-p\\s*(\\S+)",
  "PubNub Publish Key": "\\b(pub-c-[a-z0-9]{8}(?:-[a-z0-9]{4}){3}-[a-z0-9]{12})\\b",
  "PubNub Subscription Key": "\\b(sub-c-[a-z0-9]{8}(?:-[a-z0-9]{4}){3}-[a-z0-9]{12})\\b",
  "Pulumi API Key": "\\b(pul-[a-f0-9]{40})\\b",
  "PyPI Upload Token": "(pypi-AgEIcHlwaS5vcmc[A-Z0-9_-]{50,})\\b",
  "RabbitMQ Credential": "(?:amqps?):\\/\\/[\\S]{3,50}:([\\S]{3,50})@[-.%\\w\\/:]+\\b",
  "React App Username": "\\bREACT_APP(?:_[A-Z0-9]+)*_USER(?:NAME)?\\s*=\\s*['\"]?([^\\s'\"$]{3,})(?:[\\s'\"$]|$)",
  "React App Password": "\\bREACT_APP(?:_[A-Z0-9]+)*_PASS(?:WORD)?\\s*=\\s*['\"]?([^\\s'\"$]{6,})(?:[\\s'\"$]|$)",
  "ReadMe API Key": "\\b(rdme_([a-z0-9]{70}))\\b",
  "reCAPTCHA API Key": "recaptcha(?:.|[\\n\\r]){0,16}?\\b(6l[c-f][a-z0-9_-].{36})",
  "Replicate API Token": "\\b(r8_[A-Za-z0-9]{37})\\b",
  "RubyGems API Key": "\\b(rubygems_[a-z0-9]{42,52})\\b",
  "Runway API Key": "\\b(key_[A-Fa-f0-9]{128})\\b",
  "Salesforce Access / Refresh Token": "\\b(00[A-Z0-9]{13}![A-Z0-9._-]{90,120})",
  "Salesforce Instance URL": "\\b(?:https?://)?([0-9A-Z-]{5,128})\\.my\\.salesforce\\.com\\b",
  "Salesforce Consumer Key": "\\bconsumerKey\\b(?:.|[\\n\\r]){0,32}?\\b([A-Za-z0-9+/=._-]{16,256})\\b",
  "Salesforce Consumer Secret": "\\bconsumerSecret\\b(?:.|[\\n\\r]){0,32}?\\b([A-Za-z0-9+/=._-]{16,256})",
  "Salesforce Consumer Key and Secret": "(?:salesforce|sforce)(?:.|[\\n\\r]){0,256}?\\bconsumerKey\\b(?:.|[\\n\\r]){0,32}?\\b([A-Z0-9+/=._-]{16,256})\\b(?:.|[\\n\\r]){0,256}?\\bconsumer\\s{0,8}secret\\b(?:.|[\\n\\r]){0,32}?\\b([A-Za-z0-9+/=._-]{16,256})",
  "Sauce Labs Username": "\\bsauce(?:.|[\\n\\r]){0,16}?(?:USER|ID|NAME|CLIENT|OAUTH)(?:.|[\\n\\r]){0,16}?\\b([A-Z0-9_.-]{2,70})\\b",
  "Sauce Labs API Endpoint": "((?:api|ondemand)\\.(?:us|eu)-(?:west|east|central)-[0-9]\\.saucelabs\\.com)\\b",
  "Sauce Labs Access Key": "\\bsauce(?:.|[\\n\\r]){0,32}?(?:SECRET|PRIVATE|ACCESS|KEY|TOKEN)(?:.|[\\n\\r]){0,32}?([a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12})\\b",
  "Scale API Key": "\\b(live_[0-9a-f]{32})\\b",
  "Scale Callback Auth Key": "\\b(live_auth_[0-9a-f]{32})\\b",
  "Scalingo API Token": "\\b(tk-us-[\\w-]{48})",
  "Segment Public API Token": "\\b(sgp_[A-Z0-9_-]{60,70})\\b",
  "Segment API Key": "(?:segment|sgmt)(?:.|[\\n\\r]){0,16}?(?:SECRET|PRIVATE|ACCESS|KEY|TOKEN)(?:.|[\\n\\r]){0,16}?\\b([A-Z0-9_-]{40,50}\\.[A-Z0-9_-]{40,50})",
  "Sendbird Application ID": "sendbird(?:.|[\\\\n\\r]){0,32}?(?:APPLICATION|APP_ID|APP|CLIENT|ID)(?:.|[\\n\\r]){0,32}?\\b([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})\\b",
  "Sendbird API Token": "sendbird(?:.|[\\\\n\\r]){0,32}?(?:SECRET|PRIVATE|ACCESS|KEY|TOKEN)(?:.|[\\n\\r]){0,32}?\\b([a-f0-9]{40})\\b",
  "Sendgrid API token": "\\b(SG\\.[0-9A-Z_-]{20,24}\\.[0-9A-Z_-]{39,47})",
  "Sendinblue API Token": "\\b(xkeysib-[a-f0-9]{64}-[a-z0-9]{16})\\b",
  "Sentry Access Token": "sentry(?:.|[\\n\\r]){0,32}?(?:SECRET|PRIVATE|ACCESS|KEY|TOKEN)(?:.|[\\n\\r]){0,32}?\\b([a-f0-9]{64})\\b",
  "Sentry Organization Token": "(sntrys_eyJpYXQiO[a-zA-Z0-9+/]{10,200}(?:LCJyZWdpb25fdXJs|InJlZ2lvbl91cmwi|cmVnaW9uX3VybCI6)[a-zA-Z0-9+/]{10,200}={0,2}_[a-zA-Z0-9+/]{43})",
  "Sentry User Token": "(sntryu_[a-f0-9]{64})",
  "Shippo API Token": "\\b(shippo_(?:live|test)_[a-f0-9]{40})\\b",
  "SHODAN API Key": "\\bshodan(?:.|[\\n\\r]){0,32}?(?:SECRET|PRIVATE|ACCESS|KEY|TOKEN)(?:.|[\\n\\r]){0,32}?\\b([A-Z0-9]{32})\\b",
  "Shopify access token": "\\b((?:shpat|shpca|shppa|shpss)_[a-f0-9]{30,34})\\b",
  "Shopify Domain": "([a-z0-9-]+\\.myshopify\\.com)",
  "Slack App Token": "(?:.{0,24}[=:]\\s{0,8})?(xapp-[0-9]{1,3}-[0-9a-z]{10,15}-[0-9a-z]{10,15}-[0-9a-z]{10,66})\\b",
  "Snyk API Key": "\\bsnyk(?:.|[\\n\\r]){0,32}?(?:SECRET|PRIVATE|ACCESS|KEY|TOKEN)(?:.|[\\n\\r]){0,32}?([A-Z0-9]{8}-(?:[A-Z0-9]{4}-){3}[A-Z0-9]{12})\\b",
  "SonarCloud API Token": "\\bsonar(?:.|[\\n\\r]){0,32}?(?:SECRET|PRIVATE|ACCESS|KEY|TOKEN)(?:.|[\\n\\r]){0,32}?\\b([0-9a-z]{40})\\b",
  "SonarQube API Key": "\\b((?:sq[pua])_[a-z0-9]{40})\\b",
  "SonarQube Host": "sonar.{0,8}host(?:.|[\\n\\r]){0,64}?(https?://.*?:\\d{2,6})",
  "Sourcegraph Access Token": "\\b(sgp_(?:[a-f0-9]{16}_local_)?[a-f0-9]{40})\\b",
  "Sourcegraph _Legacy_ API Key": "\\bsourcegraph(?:.|[\\n\\r]){0,32}?(?:SECRET|PRIVATE|ACCESS|KEY|TOKEN)(?:.|[\\n\\r]){0,32}?((?:sgp_(?:[a-f0-9]{16}_local_)?[a-f0-9]{40}|[a-f0-9]{40}))\\b",
  "Sourcegraph Cody Gateway Key": "\\bslk_[a-f0-9]{64}\\b",
  "Square Access Token": "\\bsquare(?:.|[\\n\\r]){0,16}?\\b(EAAA[a-z0-9\\-\\+=]{60})\\b",
  "Square OAuth Secret": "\\b(sq0csp-[a-z0-9_-]{43})\\b",
  "Stability AI API Key": "\\b(sk-[A-Za-z0-9]{48})\\b",
  "StackHawk API Key": "\\b(hawk\\.[0-9A-Z_-]{20}\\.[0-9A-Z_-]{20})\\b",
  "Stripe Publishable Key": "(?:stripe|strp)(?:.|[\\n\\r]){0,16}?(?:SECRET|PRIVATE|ACCESS|KEY|TOKEN)(?:.|[\\n\\r]){0,16}?(pk_live_(?:[0-9A-Z]{6}){4,30})",
  "Stripe Secret / Restricted Key": "(?:stripe|strp)(?:.|[\\n\\r]){0,16}?(?:SECRET|PRIVATE|ACCESS|KEY|TOKEN)(?:.|[\\n\\r]){0,16}?((?:sk|rk)_live_(?:[0-9A-Z]{8}){3,25})",
  "Supabase Management Token": "(sbp_[a-z0-9_-]{40})",
  "Supabase Project API Key": "(sb_secret_[a-z0-9_-]{31})",
  "Supabase Project URL": "\\b(https:\\/\\/[a-z0-9]{16,32}\\.supabase\\.co)\\b",
  "Tailscale API Key": "\\b(tskey-[a-z]{3,10}-[A-Z0-9_-]{20,36})\\b",
  "Tavily API Key": "\\b(tvly-[a-zA-Z0-9]{32})\\b",
  "TeamCity API Token": "\\b(eyJ0eXAiOiAiVENWMiJ9\\.[A-Za-z0-9_-]{36}\\.[A-Za-z0-9_-]{48})\\b",
  "ThingsBoard Access Token": "\\bthingsboard\\.cloud/api/v1/([a-z0-9]{20})\\b",
  "ThingsBoard Provision Device Key": "\"provisionDeviceKey\"\\s*:\\s*\"([a-z0-9]{20})\\b",
  "ThingsBoard Provision Device Secret": "\"provisionDeviceSecret\"\\s*:\\s*\"([a-z0-9]{20})\\b",
  "Together.ai API Key": "\\b(tgp_v1_[A-Z0-9_-]{43})\\b",
  "Travis CI Token": "\\btravis(?:.|[\\\\n\\r]){0,16}?(?:SECRET|PRIVATE|ACCESS|KEY|TOKEN)(?:.|[\\n\\r]){0,16}?\\b([A-Z-_0-9]{22})\\b",
  "Travis CI Encrypted Variable": "(?:language|env|deploy|script):[\\r\\n](?:.|[\\\\n\\r]){0,256}?(secure:\\s*\"?[A-Za-z0-9+/=\\\\]+\"?\\s*)\\b",
  "TrueNAS API Key (WebSocket)": "\"params\"\\s*:\\s*\\[\\s*\"(\\d+-[a-zA-Z0-9]{64})\"\\s*\\]",
  "TrueNAS API Key (REST API)": "Bearer\\s*(\\d+-[a-zA-Z0-9]{64})\\b",
  "Twilio API ID": "\\b((?:SK|AC)[A-F0-9]{32})\\b",
  "Twitch API Token": "twitch(?:.|[\\n\\r]){0,32}?\\b([a-z0-9]{30})\\b",
  "X / Twitter Bearer Token (App-only)": "\\b(?:twitter|x.com|twtr)?(?:.|[\\n\\r]){0,16}?(?:SECRET|PRIVATE|ACCESS|KEY|TOKEN|BEARER)(?:.|[\\n\\r]){0,16}?\\b(A{10,}[A-Za-z0-9_\\-]{40,200})\\b",
  "Twitter Consumer Key": "\\btwitter(?:.|[\\n\\r]){0,32}?(?:SECRET|PRIVATE|ACCESS|KEY|TOKEN)(?:.|[\\n\\r]){0,32}?([A-Z0-9]{25})",
  "X / Twitter Consumer Secret": "\\btwitter(?:.|[\\n\\r]){0,32}?(?:SECRET|PRIVATE|ACCESS|KEY|TOKEN)(?:.|[\\n\\r]){0,32}?([A-Z0-9]{50})",
  "Typeform API Token": "\\btypeform(?:.|[\\n\\r]){0,32}?(tfp_[a-z0-9_\\-=\\.]{59})",
  "URI with Username and Secret": "((?:https?)://[A-Za-z](?:[A-Za-z0-9+\\-._~!$&'()*+,;=]|%[0-9A-Fa-f]{2})*:(?:[A-Za-z0-9\\-._~!$&'()*+,;=]|%[0-9A-Fa-f]{2})+@(?:[A-Za-z0-9\\-._~%]+|\\[[A-Fa-f0-9:.]+\\]|\\[v[A-Fa-f0-9][A-Za-z0-9\\-._~%!$&'()*,;=:]+\\])(:?[0-9]+)?(?:/[A-Za-z0-9\\-._~%!$&'()*,;=:@%]*)*/?(?:\\?[A-Za-z0-9\\-._~%!$&'()*,;=:@/?%]*)?(?:\\#[A-Za-z0-9\\-._~%!$&'()*,;=:@/?%]*)?)",
  "Vercel API Token": "\\bvercel(?:.|[\\n\\r]){0,32}?\\b([A-Z0-9]{24})\\b",
  "Credentials in Connect-VIServer Invocation": "Connect-VIServer.{0,50}-User\\s+(\\S{3,30}).{0,50}-Password\\s+(\\S{3,30})",
  "Voyage AI API Key": "(pa-[a-zA-Z0-9\\-_]{43})\\b",
  "Weights and Biases API Key": "(?:wandb|weightsandbiases)(?:.|[\\n\\r]){0,16}?\\b([a-f0-9]{40})\\b",
  "WireGuard Private Key": "PrivateKey\\s*=\\s*([A-Za-z0-9+/]{43}=)",
  "WireGuard Preshared Key": "PresharedKey\\s*=\\s*([A-Za-z0-9+/]{43}=)",
  "xAI (Grok) API Key": "\\b(xai-[A-Za-z0-9_-]{70,120})\\b",
  "YouTube API Key": "\\b(AIza[a-zA-Z0-9_\\-\\\\]{35})\\b",
  "Zhipu (BigModel) API Key": "\\b([A-F0-9]{32}\\.[A-Z0-9]{16})\\b",
  "Zuplo API Key": "\\b(zpka_([a-z0-9]{32})_([0-9a-f]{8}))",
  "Facebook OAuth Token": "[fF][aA][cC][eE][bB][oO][oO][kK].{0,20}['|\"][0-9a-f]{32}['|\"]",
  "GitHub Auth Credentials (URL)": "https:\\/\\/[a-zA-Z0-9]{40}@github\\.com",
  "PayPal Braintree Access Token": "access_token\\$production\\$[0-9a-z]{16}\\$[0-9a-f]{32}",
  "Picatic API Key": "sk_live_[0-9a-z]{32}",
  "AWS Session Token": "\\bFQoGZXIvYXdzE[0-9A-Za-z+/=]{10,}\\b",
  "Stripe Webhook Secret": "\\bwhsec_[A-Za-z0-9]{32,64}\\b",
  "OpenRouter API Key": "\\b(sk-or-v1-[A-Za-z0-9]{32,})\\b",
  "Supabase JWT API Key (anon/service_role)": "(?:supabase|SUPABASE)(?:.|[\\n\\r]){0,80}\\b(eyJ[A-Za-z0-9_-]{20,}\\.[A-Za-z0-9_-]{20,}\\.[A-Za-z0-9_-]{20,})\\b",
  "Firebase Web API Key": "(?:firebase|FIREBASE)(?:.|[\\n\\r]){0,64}\\b(AIza[0-9A-Za-z\\-_]{35})\\b",
  "Firebase Cloud Messaging Server Key": "\\b(AAAA[A-Za-z0-9_-]{7}:[A-Za-z0-9_-]{140})\\b",
  "Firebase Realtime Database URL": "\\bhttps://[a-z0-9-]+(?:-[a-z0-9-]+)?\\.firebaseio\\.com\\b",
  "Firebase Hosting Domain": "\\b(?:https?:\\/\\/)?[a-z0-9-]+\\.firebaseapp\\.com\\b",
  "Azure SAS Token (Blob/Storage)": "(?:azure|blob\\.core\\.windows\\.net|dfs\\.core\\.windows\\.net|queue\\.core\\.windows\\.net)(?:.|[\\n\\r]){0,200}\\b((?:sv=[0-9A-Za-z%.-]{3,20}&[^\\s\\\"']*?sig=[0-9A-Za-z%/+._-]{16,})|(?:sig=[0-9A-Za-z%/+._-]{16,}&[^\\s\\\"']*?sv=[0-9A-Za-z%.-]{3,20}))\\b",
  "Cloudflare Global API Key": "\\b(?:cloudflare|x-auth-key)(?:.|[\\n\\r]){0,32}?\\b([a-f0-9]{37,40})\\b",
  "OpenSSH Private Key Block": "(-----BEGIN OPENSSH PRIVATE KEY-----[A-Za-z0-9+/=\\r\\n]{80,}-----END OPENSSH PRIVATE KEY-----)",
  "PKCS8 Encrypted Private Key": "(-----BEGIN ENCRYPTED PRIVATE KEY-----[A-Za-z0-9+/=\\r\\n]{32,}-----END ENCRYPTED PRIVATE KEY-----)",
  "Google OAuth Refresh Token": "\\b(1\\/\\/[0-9A-Za-z_-]{30,})\\b",
  "Salesforce Refresh Token": "(?:salesforce|sfdc)(?:.|[\\n\\r]){0,80}?(?:refresh[_\\s-]*token)(?:.|[\\n\\r]){0,24}?\\b([A-Za-z0-9._-]{80,220})\\b",
  "PostgreSQL URI with Credentials": "\\bpostgres(?:ql)?:\\/\\/(?:[a-z0-9._%+\\-]+):(?:[^\\s:@\\/]+)@(?:\\[[0-9a-f:.]+\\]|[a-z0-9.-]+)(?::\\d{2,5})?(?:\\/[a-z0-9._%+\\-]+)?(?:\\?[^\\s\\\"']*)?\\b",
  "MSSQL URI with Credentials": "\\b(?:mssql|sqlserver):\\/\\/(?:[a-z0-9._%+\\-]+):(?:[^\\s:@\\/]+)@(?:\\[[0-9a-f:.]+\\]|[a-z0-9.-]+)(?::\\d{2,5})?(?:\\/[a-z0-9._%+\\-]+)?(?:\\?[^\\s\\\"']*)?\\b",
  "SQL URL with Credentials (Generic)": "\\b(?:mysql|mariadb|postgres(?:ql)?|mssql|sqlserver):\\/\\/(?:[a-z0-9._%+\\-]+):(?:[^\\s:@\\/]+)@(?:\\[[0-9a-f:.]+\\]|[a-z0-9.-]+)(?::\\d{2,5})?(?:\\/[a-z0-9._%+\\-]+)?(?:\\?[^\\s\\\"']*)?\\b",
  "SQL Host + Password Pair": "(?:db[_\\s-]*host|database[_\\s-]*host|sql[_\\s-]*host)(?:.|[\\n\\r]){0,40}?([a-z0-9.-]{3,253})(?:.|[\\n\\r]){0,40}?(?:db[_\\s-]*pass|database[_\\s-]*pass|sql[_\\s-]*pass|password)(?:.|[\\n\\r]){0,20}?([A-Za-z0-9!@#$%^&*()_+\\-={}:;\"'<>?,./]{6,120})",
  "Cloudsmith API Key": "\\bcloudsmith(?:.|[\\n\\r]){0,32}?(?:SECRET|PRIVATE|ACCESS|KEY|TOKEN)?(?:.|[\\n\\r]){0,16}?\\b([a-f0-9]{40})\\b",
  "ClickUp Personal Token": "\\b(pk_[0-9]{7,9}_[0-9A-Z]{32})\\b",
  "Detectify API Key": "\\bdetectify(?:.|[\\n\\r]){0,24}?\\b([0-9a-z]{32})\\b",
  "Azure API Management Subscription Key": "(?:azure|\\.azure-api\\.net|subscription(?:_|\\s|-)?key)(?:.|[\\n\\r]){0,32}?\\b([A-Za-z0-9]{32})\\b",
  "Azure Function Key": "\\bhttps:\\/\\/[a-z0-9-]{2,30}\\.azurewebsites\\.net\\/api\\/[a-z0-9-]{2,30}\\?code=([A-Za-z0-9_-]{20,56}={0,2})\\b",
  "PII - China ID Card Number (FindSomething)": "['\"]([1-9][0-9]{5}(?:18|19|20)[0-9]{2}(?:0[1-9]|1[0-2])(?:0[1-9]|[12][0-9]|3[01])[0-9]{3}[0-9Xx])['\"]",
  "PII - China Mobile Number (FindSomething)": "['\"](1(3([0-35-9]\\d|4[1-8])|4[14-9]\\d|5([\\d]\\d|7[1-79])|66\\d|7[2-35-8]\\d|8\\d{2}|9[89]\\d)\\d{7})['\"]",
  "PII - Email Address (FindSomething Style)": "['\"]([a-zA-Z0-9._%+-]{1,64}@[a-zA-Z0-9.-]{1,253}\\.(?!js|css|jpg|jpeg|png|ico\\b)[a-zA-Z]{2,24})['\"]",
  "PII - US Social Security Number (Contextual)": "(?:\\bssn\\b|social[_\\s-]*security(?:[_\\s-]*number)?)(?:.|[\\n\\r]){0,20}\\b((?!000|666|9\\d\\d)\\d{3}[- ]?(?!00)\\d{2}[- ]?(?!0000)\\d{4})\\b",
  "PII - Payment Card Number (Contextual)": "(?:\\bcredit[_\\s-]*card\\b|\\bcard[_\\s-]*number\\b|\\bcc[_\\s-]*number\\b|\\bvisa\\b|\\bmastercard\\b|\\bamex\\b)(?:.|[\\n\\r]){0,20}\\b((?:4\\d{3}|5[1-5]\\d{2}|3[47]\\d{2}|6(?:011|5\\d{2}))(?:[ -]?\\d{4}){2}(?:[ -]?\\d{3,4})?)\\b",
  "PII - IBAN (Contextual)": "(?:\\biban\\b|international[_\\s-]*bank[_\\s-]*account)(?:.|[\\n\\r]){0,20}\\b([A-Z]{2}[0-9]{2}[A-Z0-9]{11,30})\\b",
  "PII - Aadhaar Number (Contextual)": "(?:\\baadhaar\\b|\\buidai\\b|\\buid\\b)(?:.|[\\n\\r]){0,20}\\b([2-9][0-9]{3}[ -]?[0-9]{4}[ -]?[0-9]{4})\\b",
  "Firebase Config Key": "(?:apiKey|api_key)\\s*[:=]\\s*['|\"](AIza[0-9A-Za-z\\-_]{35})['|\"]",
  "Generic Key/Token (Broad)": "(?:key|token|secret|auth|pwd|password|pass|api)\\b.{0,20}['|\"]([0-9a-zA-Z\\-_]{24,64})['|\"]",
  "EndPointer - API Endpoint": "['\"](?:\\/api\\/|\\/v[0-9]+\\/|\\/(?:graphql|rest)\\/|[^\"'\\s]+\\.(?:json|xml))['\"]",
  "EndPointer - User Data Access": "['\"](?:\\/users?\\/[^\\/\"']+|\\/profiles?\\/|\\/accounts?\\/|\\/personal)['\"]",
  "EndPointer - Database Operation": "['\"](?:\\/(?:query|insert|update|delete)|\\/db\\/|\\/data\\/)['\"]",
  "EndPointer - Sensitive Data (URL)": "['\"](?:\\/(?:password|secret|key|token|auth|credentials|jwt|bearer)|\\/(?:secure|security|confidential)|\\/private\\/|\\/(?:ssn|social-security|personal-info|pii|personal)|\\.env(?:\\.local)?|config(?:\\.json|\\.yaml|\\.yml|\\.xml|\\.js|\\.env)?|settings(?:\\.json|\\.yaml|\\.yml|\\.xml|\\.js)?|\\/(?:backup|dump|export|archive|db-backup)|[^\"'\\s]+\\.(?:pem|crt|cer|pfx|p12))['\"]",
  "EndPointer - Unsecured API": "['\"](?:http:\\/\\/|\\/public-api\\/|\\/open-api\\/|\\/test-api\\/)['\"]",
  "EndPointer - Authentication Endpoint": "['\"](?:\\/(?:auth|login|logout|signin|signup|register)|\\/oauth|\\/jwt\\/|\\/(?:session|token))['\"]",
  "EndPointer - Data Transfer": "['\"](?:\\/(?:upload|download|transfer|export|import)|\\/stream\\/|\\/webhook)['\"]",
  "EndPointer - Admin Panel": "['\"](?:\\/(?:admin|administrator|manage|console|dashboard)|\\/cms\\/|\\/control-panel)['\"]",
  "EndPointer - Payment Processing": "['\"](?:\\/(?:payment|checkout|billing|invoice)|\\/transaction|\\/(?:stripe|paypal|square))['\"]",
  "EndPointer - File Access": "['\"](?:\\/(?:files?|documents?|uploads?)|\\/storage\\/|[^\"'\\s]+\\.(?:pdf|doc|xls|csv))['\"]",
  "EndPointer - Legacy Endpoint": "['\"](?:\\/legacy\\/|\\/old-api\\/|\\/v[0-9]\\.|\\/deprecated\\/)['\"]",
  "EndPointer - Debug Endpoint": "['\"](?:\\/(?:debug|test|dev)|\\/logs?\\/|\\/metrics\\/|\\/health-?check)['\"]",
  "EndPointer - Potentially Vulnerable": "['\"](?:(?:\\/(?:admin|config|setup|install)\\.php$)|(?:\\/(?:sql|shell|cmd))|(?:\\/(?:eval|exec))|(?:\\?.*=(?:https?:\\/\\/|\\/\\/)))['\"]",
  "Sentry DSN": "https:\\/\\/[a-f0-9]{32}@(?:o[0-9]+\\.)?ingest\\.sentry\\.io\\/[0-9]+",
  "Resend API Key": "\\b(re_[A-Za-z0-9]{24,36})\\b",
  "Clerk Secret Key": "\\b(sk_live_[A-Za-z0-9]{32,60}|sk_test_[A-Za-z0-9]{32,60})\\b",
  "Cloudinary URL with Credentials": "cloudinary:\\/\\/[0-9]+:[a-zA-Z0-9_\\-]+@[a-zA-Z0-9_\\-]+",
  "AWS S3 Bucket URL": "\\bhttps?:\\/\\/(?:[a-z0-9.-]+\\.s3(?:-accelerate)?(?:\\.[a-z0-9-]+)?\\.amazonaws\\.com|[a-z0-9.-]+\\.s3\\.[a-z0-9-]+\\.amazonaws\\.com\\/[^\\s\"'>]+)\\b",
  "GCP Cloud Storage Bucket URL": "\\bhttps?:\\/\\/storage\\.googleapis\\.com\\/[a-z0-9_.-]+(?:\\/[^\\s\"'>]+)?\\b",
  "Upstash Redis / QStash Token": "\\b(upstash_[a-zA-Z0-9_]{32,64})\\b",
  "Plaid Client ID / Secret": "(?i:plaid).{0,30}(?:secret|client_id).{0,20}['\"]([a-f0-9]{30})['\"]",
  "Censys API Key / Secret": "(?i:censys).{0,30}(?:secret|token|key).{0,20}['\"]([a-zA-Z0-9_-]{32})['\"]",
  "VirusTotal API Key": "(?i:virustotal|vt_api_key).{0,30}['\"]([a-f0-9]{64})['\"]",
  "SecurityTrails API Key": "(?i:securitytrails).{0,30}['\"]([a-zA-Z0-9]{32})['\"]",
  "Source Map Reference": "(?:\\/\\/[#@]\\s*sourceMappingURL=|\\/\\*#\\s*sourceMappingURL=)\\s*([^\\s*'\"\\*]+\\.map)"
};


class KatanaSecretScanner {
  constructor() {
    this.compiledRules = [];
    this.initRules();
  }

  initRules() {
    for (const [name, pattern] of Object.entries(KATANA_SECRET_RULES)) {
      try {
        const rx = new RegExp(pattern, 'g');
        const severity = this.calculateSeverity(name);
        const category = this.calculateCategory(name);
        this.compiledRules.push({ name, pattern, rx, severity, category });
      } catch (err) {
        console.warn('[KatanaSecretScanner] Skipped regex:', name, err.message);
      }
    }
  }

  calculateSeverity(name) {
    const n = name.toLowerCase();
    if (n.includes('private key') || n.includes('aws secret') || n.includes('stripe secret') || 
        n.includes('password hash') || n.includes('connection string with') || n.includes('uri with credentials') || 
        n.includes('hardcoded password') || n.includes('admin api key') || n.includes('service account')) {
      return 'critical';
    }
    if (n.includes('aws') || n.includes('google') || n.includes('slack token') || n.includes('github') || 
        n.includes('gitlab') || n.includes('openai') || n.includes('anthropic') || n.includes('sentry dsn') || 
        n.includes('api key') || n.includes('access token') || n.includes('secret key') || n.includes('resend') || 
        n.includes('clerk') || n.includes('upstash') || n.includes('cloudinary') || n.includes('datadog') || 
        n.includes('twilio') || n.includes('stripe') || n.includes('firebase config')) {
      return 'high';
    }
    if (n.includes('webhook') || n.includes('client secret') || n.includes('bearer') || n.includes('jwt') || 
        n.includes('auth') || n.includes('token') || n.includes('plaid') || n.includes('censys') || n.includes('shodan')) {
      return 'medium';
    }
    if (n.includes('source map') || n.includes('s3 bucket') || n.includes('storage bucket') || 
        n.includes('client id') || n.includes('domain') || n.includes('host') || n.includes('url') || 
        n.includes('endpoint') || n.includes('pii')) {
      return 'info';
    }
    return 'medium';
  }

  calculateCategory(name) {
    const n = name.toLowerCase();
    if (n.includes('private key') || n.includes('rsa') || n.includes('ssh') || n.includes('pgp') || n.includes('pem') || n.includes('openssh')) return 'private-key';
    if (n.includes('aws') || n.includes('azure') || n.includes('gcp') || n.includes('google') || n.includes('alibaba') || n.includes('digitalocean') || n.includes('cloudflare') || n.includes('s3') || n.includes('storage')) return 'cloud';
    if (n.includes('postgres') || n.includes('mysql') || n.includes('sql') || n.includes('mongo') || n.includes('redis') || n.includes('database') || n.includes('jdbc') || n.includes('odbc')) return 'database';
    if (n.includes('pii') || n.includes('social security') || n.includes('card number') || n.includes('iban') || n.includes('email')) return 'pii';
    if (n.includes('source map')) return 'source-map';
    if (n.includes('password') || n.includes('pass') || n.includes('credential')) return 'credential';
    if (n.includes('webhook')) return 'webhook';
    if (n.includes('token') || n.includes('jwt') || n.includes('bearer')) return 'token';
    return 'api-key';
  }

  isNoise(match, ruleName) {
    if (!match || typeof match !== 'string') return true;
    const clean = match.trim();
    if (clean.length < 5) return true;

    const lower = clean.toLowerCase();

    // 1. Definite placeholder words (substring check)
    const placeholderWords = [
      'your_api_key', 'your-api-key', 'yourapikey', 'your_token', 'your-token',
      'your_secret', 'your-secret', 'my_api_key', 'my-api-key', 'mysecret',
      'insert_here', 'replace_me', 'changeme', 'change_me',
      'sample_key', 'test_key', 'dummy_key', 'placeholder',
      'current-password', 'new-password', 'user_password'
    ];
    for (const p of placeholderWords) {
      if (lower.includes(p)) return true;
    }

    // Exact matches for dummy sequences
    const exactDummies = [
      'undefined', 'null', 'false', 'true', 'default', 'none', 'unknown',
      'password', 'password123', 'admin', 'root', '12345678', '1234567890', 'abcdefgh'
    ];
    if (exactDummies.includes(lower)) return true;

    // 2. Repetitive characters check (e.g. 'aaaaaaa', '1111111', 'xxxxxxxx')
    if (/^(.)\1{5,}$/i.test(clean)) return true;
    if (lower.includes('xxxxxxxx') || lower.includes('00000000')) return true;

    // 3. SVG Path data detection
    if (/^[MmLlHhVvCcSsQqTtAaZz0-9,\.\s-]+$/.test(clean) && (clean.startsWith('M') || clean.startsWith('m')) && clean.length > 30) {
      return true;
    }

    // 4. CSS token / font-family / color check
    if (clean.startsWith('#') && /^[0-9a-fA-F]{3,8}$/.test(clean)) return true;
    if (clean.startsWith('rgb(') || clean.startsWith('rgba(') || clean.startsWith('hsl(')) return true;
    if (/^(?:flex|grid|block|inline|none|hidden|center|relative|absolute|pointer|solid|dashed)$/i.test(clean)) return true;

    // 5. Filter trivial EndPointer noise
    if (ruleName.startsWith('EndPointer')) {
      const sensitiveKeywords = ['.env', 'config', 'backup', 'secret', 'token', 'auth', 'admin', 'eval', 'exec', 'setup', 'dump', 'key', 'pem', 'crt'];
      const hasSensitive = sensitiveKeywords.some(k => lower.includes(k));
      if (!hasSensitive) return true;
    }

    // 6. Generic password / secret validator
    if (ruleName === 'Generic Password' || ruleName === 'Generic Secret' || ruleName === 'Generic API Key') {
      const hasLetter = /[a-zA-Z]/.test(clean);
      const hasDigit = /[0-9]/.test(clean);
      if (!hasLetter || !hasDigit) return true;
      if (clean.length < 10) return true;
    }

    return false;
  }

  maskSecret(secret) {
    if (!secret || secret.length <= 8) return '••••••••';
    const len = secret.length;
    if (len <= 14) {
      return secret.slice(0, 2) + '••••' + secret.slice(-2);
    }
    const visiblePrefix = Math.min(6, Math.floor(len * 0.15));
    const visibleSuffix = Math.min(4, Math.floor(len * 0.1));
    return secret.slice(0, visiblePrefix) + '••••••••' + secret.slice(-visibleSuffix);
  }

  extractContext(content, matchIndex, matchLength) {
    const start = Math.max(0, matchIndex - 60);
    const end = Math.min(content.length, matchIndex + matchLength + 60);
    let snippet = content.slice(start, end).replace(/[\r\n]+/g, ' ').trim();
    if (start > 0) snippet = '...' + snippet;
    if (end < content.length) snippet = snippet + '...';
    return snippet;
  }

  scan(content, sourceUrl, sourceType = 'html') {
    if (!content || typeof content !== 'string' || content.length < 5) {
      return [];
    }

    // Limit scanning size per file to 3MB for high performance
    const textToScan = content.length > 3000000 ? content.slice(0, 3000000) : content;
    const findings = [];
    const seenMatches = new Set();

    for (const rule of this.compiledRules) {
      rule.rx.lastIndex = 0;
      let m;
      let count = 0;

      while ((m = rule.rx.exec(textToScan)) !== null && count < 10) {
        count++;
        let rawMatch = (m[1] || m[0] || '').trim();
        rawMatch = rawMatch.replace(/^["'\s`({[]+|["'\s`)\]}]+$/g, '');

        if (!rawMatch || this.isNoise(rawMatch, rule.name)) {
          continue;
        }

        const dedupKey = rawMatch;
        if (seenMatches.has(dedupKey)) {
          continue;
        }
        seenMatches.add(dedupKey);

        const matchIdx = m.index;
        const context = this.extractContext(textToScan, matchIdx, m[0].length);

        findings.push({
          ruleName: rule.name,
          severity: rule.severity,
          category: rule.category,
          match: rawMatch,
          masked: this.maskSecret(rawMatch),
          context: context,
          sourceUrl: sourceUrl,
          sourceType: sourceType,
          discoveredAt: Date.now()
        });
      }
    }

    return findings;
  }

  static extractSourceMapUrls(text, baseUrl) {
    if (!text || typeof text !== 'string') return [];
    const mapUrls = [];
    const smRegex = /(?:\/\/[#@]\s*sourceMappingURL=|\/\*#\s*sourceMappingURL=)\s*([^\s*'"\*]+\.map)/gi;
    let m;
    while ((m = smRegex.exec(text)) !== null) {
      const rel = m[1].trim();
      try {
        const abs = new URL(rel, baseUrl).toString();
        mapUrls.push(abs);
      } catch {}
    }
    return mapUrls;
  }
}

if (typeof window !== 'undefined') {
  window.KatanaSecretScanner = KatanaSecretScanner;
  window.katanaSecretScanner = new KatanaSecretScanner();
}
if (typeof module !== 'undefined' && module.exports) {
  module.exports = { KatanaSecretScanner };
}
