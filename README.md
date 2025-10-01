# Dashboard de Tráfego de Rede (versão Excel)


#Alunos
01: Othon Flávio Alves de Sales - 2312130178


02: Mariana Paiva de Souza Moreira - 2312130137
## 📖 Descrição
Este projeto implementa um dashboard para análise de tráfego de rede, originalmente proposto como aplicação web.  
Com base no ajuste permitido pelo professor, a interface cliente foi desenvolvida no **Excel**, utilizando **tabelas dinâmicas e gráficos dinâmicos** para exploração dos dados.


O sistema recebe como entrada um arquivo **CSV** contendo registros de tráfego de rede (timestamp, IP do cliente, protocolo, bytes e pacotes).  
Esse arquivo pode ser aberto no Excel, onde é possível explorar e visualizar os dados de forma interativa.


---


## 🗂 Estrutura do Projeto
- `traffic_data.csv` → Arquivo de entrada com os dados de tráfego de rede.  
- `dashboard.xlsx` → Arquivo Excel com tabelas dinâmicas e gráficos configurados.  
- `relatorio_tecnico.pdf` → Documento explicativo da arquitetura e desafios do projeto.  


---


## ⚙️ Como Utilizar
1. Gere ou utilize o arquivo `traffic_data.csv`.  
   - O CSV deve conter as colunas:  
     - **Timestamp**  
     - **Client_IP**  
     - **Protocol**  
     - **Bytes_In**  
     - **Bytes_Out**  
     - **Packets_In**  
     - **Packets_Out**


2. Abra o arquivo **dashboard.xlsx** no Excel.  


3. Atualize a tabela dinâmica:  
   - Vá em **Analisar → Atualizar Tudo** para carregar os novos dados do CSV.  


4. Explore o dashboard:  
   - **Gráfico de barras** → mostra Bytes In/Out agrupados por IP.  
   - **Drill down** → clicando em um IP, o Excel mostra os protocolos usados por aquele cliente.  
   - **Filtros temporais** → utilize segmentações (ou filtros da tabela dinâmica) para analisar por intervalos de tempo.


---


## 🔍 Observações
- O sistema foi projetado para trabalhar com **janelas de 5 segundos**. Isso é representado na coluna **Timestamp** do CSV.  
- O Excel já trata automaticamente a exploração dos dados com drill down.  
- Caso queira personalizar as visualizações, basta inserir novos gráficos vinculados às tabelas dinâmicas.





