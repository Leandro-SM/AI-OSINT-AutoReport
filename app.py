import streamlit as st
from PIL import Image
import exifread
import hashlib
import urllib.parse
from datetime import datetime
import tempfile
from fpdf import FPDF

st.set_page_config(
    page_title="OSINT Framework",
    page_icon="🕵️",
    layout="wide"
)

st.markdown("## 🕵️ OSINT Framework")
st.caption("Ferramentas de Análise e Dorking")
st.caption("https://www.linkedin.com/in/leandro-medeiros-ti/")
st.divider()

INSECAM_COUNTRIES = {
    "Brazil - BR": "br",
    "Canada - CA": "ca",
    "United States - US": "us",
    "Germany - DE": "de",
    "France - FR": "fr",
    "Italy - IT": "it",
    "Spain - ES": "es",
    "Japan - JP": "jp",
    "Russia - RU": "ru"
}

def sanitize_cnpj(cnpj):
    return "".join(filter(str.isdigit, cnpj))

def google_search_url(query):
    return f"https://www.google.com/search?q={urllib.parse.quote(query)}"

def generate_google_dorks(term):
    quoted_term = f'"{term}"'
    site_term = f"site:{term}"

    return {
        "Menções Diretas (Texto)": [
            quoted_term,
            f'{quoted_term} password',
            f'{quoted_term} senha',
            f'{quoted_term} credentials',
            f'{quoted_term} leaked',
            f'{quoted_term} cpf',
            f'{quoted_term} email'
        ],
        "Arquivos Relacionados": [
            f'{quoted_term} filetype:pdf',
            f'{quoted_term} filetype:xls',
            f'{quoted_term} filetype:doc',
            f'{quoted_term} filetype:txt'
        ],
        "URLs Sensíveis (site:)": [
            f'{site_term} inurl:admin',
            f'{site_term} inurl:login',
            f'{site_term} inurl:password',
            f'{site_term} intitle:"index of"'
        ],
        "Redes Sociais": [
            f'site:instagram.com {quoted_term}',
            f'site:linkedin.com {quoted_term}',
            f'site:github.com {quoted_term}',
            f'site:reddit.com {quoted_term}'
        ]
    }

def dms_to_decimal(dms, ref):
    degrees = float(dms[0].num) / float(dms[0].den)
    minutes = float(dms[1].num) / float(dms[1].den)
    seconds = float(dms[2].num) / float(dms[2].den)
    decimal = degrees + (minutes / 60.0) + (seconds / 3600.0)
    if ref in ['S', 'W']:
        decimal = -decimal
    return decimal

def extract_metadata(uploaded_file):

    metadata = {
        "Nome do Arquivo": uploaded_file.name,
        "Tipo do Arquivo": uploaded_file.type,
        "Tamanho (Bytes)": uploaded_file.size
    }

    try:
        if uploaded_file.type.startswith("image"):

            uploaded_file.seek(0)
            image = Image.open(uploaded_file)

            metadata["Formato"] = image.format
            metadata["Modo"] = image.mode
            metadata["Dimensões"] = image.size

            uploaded_file.seek(0)
            exif_tags = exifread.process_file(uploaded_file, details=False)

            metadata["Dispositivo"] = str(exif_tags.get("Image Make", "Desconhecido"))
            metadata["Modelo"] = str(exif_tags.get("Image Model", "Desconhecido"))
            metadata["Data da Captura"] = str(exif_tags.get("EXIF DateTimeOriginal", "Desconhecido"))

            gps_latitude = exif_tags.get("GPS GPSLatitude")
            gps_latitude_ref = exif_tags.get("GPS GPSLatitudeRef")
            gps_longitude = exif_tags.get("GPS GPSLongitude")
            gps_longitude_ref = exif_tags.get("GPS GPSLongitudeRef")

            if gps_latitude and gps_latitude_ref and gps_longitude and gps_longitude_ref:

                lat = dms_to_decimal(gps_latitude.values, gps_latitude_ref.values)
                lon = dms_to_decimal(gps_longitude.values, gps_longitude_ref.values)

                metadata["GPS"] = {"Latitude": lat, "Longitude": lon}

            else:
                metadata["GPS"] = "Não disponível"

    except Exception as e:
        metadata["Erro"] = str(e)

    return metadata

def calculate_hashes(uploaded_file):

    uploaded_file.seek(0)
    data = uploaded_file.read()

    return {
        "MD5": hashlib.md5(data).hexdigest(),
        "SHA1": hashlib.sha1(data).hexdigest(),
        "SHA256": hashlib.sha256(data).hexdigest()
    }

def generate_markdown_report(metadata, hashes):

    report = f"""
Relatório Forense

Data: {datetime.now()}

Arquivo:
Nome: {metadata.get("Nome do Arquivo")}
Tipo: {metadata.get("Tipo do Arquivo")}
Tamanho: {metadata.get("Tamanho (Bytes)")}

Metadados:
Dispositivo: {metadata.get("Dispositivo")}
Modelo: {metadata.get("Modelo")}
Data da captura: {metadata.get("Data da Captura")}
Dimensões: {metadata.get("Dimensões")}

GPS:
{metadata.get("GPS")}

Hashes:
MD5: {hashes["MD5"]}
SHA1: {hashes["SHA1"]}
SHA256: {hashes["SHA256"]}

Observações:
Relatório gerado automaticamente.
"""

    return report

def markdown_to_pdf(md_text):

    pdf = FPDF()
    pdf.add_page()
    pdf.set_auto_page_break(auto=True, margin=10)
    pdf.set_font("Arial", size=12)

    lines = md_text.split("\n")

    for line in lines:
        clean_line = line.replace("#", "").replace("**", "")
        pdf.multi_cell(0, 8, clean_line)

    temp_file = tempfile.NamedTemporaryFile(delete=False, suffix=".pdf")
    pdf.output(temp_file.name)

    return temp_file.name

uploaded_file = st.file_uploader(
    "📁 Envie um arquivo para análise",
    type=["jpg", "jpeg", "png", "pdf", "txt"]
)

tab1, tab2, tab3 = st.tabs([
    "🔬 Análise Forense",
    "🌐 OSINT",
    "📄 Relatório"
])

metadata = None
hashes = None

with tab1:

    st.subheader("Metadados")

    if uploaded_file:

        col1, col2 = st.columns(2)

        with col1:
            metadata = extract_metadata(uploaded_file)
            st.json(metadata, expanded=True)

        with col2:
            hashes = calculate_hashes(uploaded_file)
            st.json(hashes)

        if uploaded_file.type.startswith("image"):
            st.image(uploaded_file)

    else:
        st.info("Envie um arquivo para iniciar a análise")

with tab2:

    st.subheader("Busca - Google Dorks")

    search_term = st.text_input("Termo de busca")

    if search_term:

        dorks = generate_google_dorks(search_term)

        for category, queries in dorks.items():

            with st.expander(category):

                for q in queries:
                    st.markdown(f"- [{q}]({google_search_url(q)})")

    st.divider()

    selected_country = st.selectbox("Câmeras", list(INSECAM_COUNTRIES.keys()))

    if selected_country:
        code = INSECAM_COUNTRIES[selected_country]
        st.markdown(f"[Acessar Insecam](http://www.insecam.org/en/bycountry/{code}/)")

    st.divider()

    cnpj_input = st.text_input("CNPJ")

    if cnpj_input:

        cnpj = sanitize_cnpj(cnpj_input)

        if len(cnpj) == 14:
            st.markdown(f"https://cadastroempresa.com.br/procura?q={cnpj}")
        else:
            st.error("CNPJ inválido")

with tab3:

    st.header("📄 Relatórios")

    if uploaded_file:

        metadata = extract_metadata(uploaded_file)
        hashes = calculate_hashes(uploaded_file)

        md_report = generate_markdown_report(metadata, hashes)

        st.download_button(
            "Baixar .md",
            md_report,
            "relatorio.md"
        )

        if st.button("Gerar PDF"):

            pdf_path = markdown_to_pdf(md_report)

            with open(pdf_path, "rb") as f:
                st.download_button(
                    "Baixar PDF",
                    f,
                    "relatorio.pdf"
                )

    else:
        st.info("Envie um arquivo para gerar relatório")
