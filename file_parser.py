import csv
import re
import pandas as pd
import pdfplumber
import os
from typing import Set, Optional, List

# Regex to find CVE IDs - Case Insensitive
# Covers CVE-YYYY-NNNN where YYYY is 1999 or 2XXX and NNNN is at least 4 digits.
CVE_PATTERN = re.compile(r"CVE-(1999|2\d{3})-(\d{4,})", re.IGNORECASE)

def extract_cves_from_text(text: str) -> Set[str]:
    """
    Extracts all unique CVE ID strings from a given block of text.
    Matches are converted to uppercase standard format.
    """
    if not text:
        return set()

    found_cves = set()
    # findall returns tuples of the capturing groups: (year_group, number_group)
    matches = CVE_PATTERN.findall(text)
    for match in matches:
        # Reconstruct the CVE string in standard uppercase format
        # match[0] is the year part (e.g., "1999" or "2023")
        # match[1] is the number part (e.g., "0001" or "12345")
        cve_id = f"CVE-{match[0]}-{match[1]}"
        found_cves.add(cve_id.upper())
    return found_cves

def parse_csv_file(file_path: str) -> Set[str]:
    """
    Parses a CSV file and extracts all unique CVE IDs.
    """
    all_cves: Set[str] = set()
    try:
        with open(file_path, mode='r', encoding='utf-8', errors='ignore') as csvfile:
            reader = csv.reader(csvfile)
            for row in reader:
                for cell in row:
                    if cell: # Ensure cell is not None
                        all_cves.update(extract_cves_from_text(str(cell)))
    except FileNotFoundError:
        print(f"Error: CSV file not found at {file_path}")
        return set()
    except Exception as e:
        print(f"Error parsing CSV file {file_path}: {e}")
        return set()
    return all_cves

def parse_excel_file(file_path: str) -> Set[str]:
    """
    Parses an Excel file (.xls or .xlsx) and extracts all unique CVE IDs from all sheets.
    """
    all_cves: Set[str] = set()
    try:
        # sheet_name=None reads all sheets
        xls = pd.read_excel(file_path, sheet_name=None, header=None) # header=None to treat all rows as data
        for sheet_name, df in xls.items():
            # print(f"  Processing sheet: {sheet_name}")
            for column in df.columns:
                # Convert entire column to string, then join, then extract.
                # This is often faster than cell-by-cell for pandas if text is dense.
                # Fill NaN with empty string to avoid errors with str conversion of NaN
                column_text = ' '.join(df[column].fillna('').astype(str).tolist())
                all_cves.update(extract_cves_from_text(column_text))
    except FileNotFoundError:
        print(f"Error: Excel file not found at {file_path}")
        return set()
    except Exception as e:
        print(f"Error parsing Excel file {file_path}: {e}")
        # This can catch issues with xlrd/openpyxl if engines are missing or file is corrupt
        if "Excel file format cannot be determined" in str(e) or "Unsupported format, or corrupt file" in str(e):
            print("  Ensure the file is a valid .xls or .xlsx file.")
        if "xlrd" in str(e).lower() and file_path.endswith('.xlsx'):
             print("  Try installing 'openpyxl' for .xlsx files.")
        if "openpyxl" in str(e).lower() and file_path.endswith('.xls'):
             print("  Try installing 'xlrd' for .xls files.")
        return set()
    return all_cves

def parse_pdf_file(file_path: str) -> Set[str]:
    """
    Parses a PDF file and extracts all unique CVE IDs.
    Assumes text-based PDF. For scanned PDFs, OCR would be needed.
    """
    all_cves: Set[str] = set()
    try:
        with pdfplumber.open(file_path) as pdf:
            full_text = []
            for i, page in enumerate(pdf.pages):
                # print(f"  Processing PDF page {i+1}/{len(pdf.pages)}")
                text = page.extract_text()
                if text:
                    full_text.append(text)
            all_cves.update(extract_cves_from_text("\n".join(full_text)))
    except FileNotFoundError:
        print(f"Error: PDF file not found at {file_path}")
        return set()
    except pdfplumber.exceptions.PDFSyntaxError:
        print(f"Error: Could not parse PDF {file_path}. It might be corrupted or not a valid PDF.")
        return set()
    except Exception as e:
        print(f"Error parsing PDF file {file_path}: {e}")
        return set()
    return all_cves

def parse_file(file_path: str) -> Optional[Set[str]]:
    """
    Detects file type and calls the appropriate parser.
    Returns a set of unique CVE IDs found, or None if file type is unsupported.
    """
    _, extension = os.path.splitext(file_path.lower())

    print(f"Attempting to parse file: {file_path} (type: {extension})")

    if extension == ".csv":
        return parse_csv_file(file_path)
    elif extension in [".xls", ".xlsx"]:
        return parse_excel_file(file_path)
    elif extension == ".pdf":
        return parse_pdf_file(file_path)
    else:
        print(f"Unsupported file type: {extension} for file {file_path}")
        return None

if __name__ == "__main__":
    # Create dummy files for testing
    TEST_DIR = "test_bulk_files"
    os.makedirs(TEST_DIR, exist_ok=True)

    dummy_csv_content = """CVE-ID,Description,Status
CVE-2023-12345,A vulnerability,Open
CVE-2023-67890,Another one,Patched
cve-2022-1111, Mixed case, CVE-2021-00000004, 8-digit
Invalid CVE-202-123,CVE-1998-0001,CVE-2024-123456789
"""
    csv_file_path = os.path.join(TEST_DIR, "test_cves.csv")
    with open(csv_file_path, "w") as f:
        f.write(dummy_csv_content)

    # For Excel, pandas is used to create the file
    # Create a Pandas Excel writer using XlsxWriter as the engine.
    excel_file_path_xlsx = os.path.join(TEST_DIR, "test_cves.xlsx")
    df1_data = {
        'ColumnA': ['Info CVE-2023-0001 here', 'CVE-2023-0002 in cell', 'no cve'],
        'ColumnB': ['Text with cve-2023-0003', 'another CVE-2022-9999', 'CVE-1999-0010']
    }
    df2_data = {
        'Sheet2Col1': ['CVE-2020-1234', 'More text and CVE-2020-5678 end']
    }
    df1 = pd.DataFrame(df1_data)
    df2 = pd.DataFrame(df2_data)

    try:
        with pd.ExcelWriter(excel_file_path_xlsx, engine='openpyxl') as writer:
            df1.to_excel(writer, sheet_name='Sheet1', index=False)
            df2.to_excel(writer, sheet_name='Sheet2', index=False)
        print(f"Created dummy Excel (.xlsx): {excel_file_path_xlsx}")
    except Exception as e:
        print(f"Could not create dummy .xlsx file: {e}. openpyxl might be needed or there's an issue.")

    # For PDF, we'll use reportlab to create a simple PDF
    # This requires `pip install reportlab`
    pdf_file_path = os.path.join(TEST_DIR, "test_cves.pdf")
    try:
        from reportlab.pdfgen import canvas
        from reportlab.lib.pagesizes import letter

        c = canvas.Canvas(pdf_file_path, pagesize=letter)
        c.drawString(72, 800, "Simple PDF for testing CVE extraction.")
        c.drawString(72, 780, "Contains CVE-2023-1000 and cve-2023-2000.")
        c.drawString(72, 760, "Also, a longer one: CVE-2022-123456.")
        c.drawString(72, 740, "And one from 1999: CVE-1999-0002.")
        c.drawString(72, 720, "Invalid one: CVE-123-456. Another valid: CVE-2024-77777.")
        c.save()
        print(f"Created dummy PDF: {pdf_file_path}")
    except ImportError:
        print("reportlab not found, skipping dummy PDF creation. pip install reportlab to create it.")
        pdf_file_path = None # Ensure it's None if not created
    except Exception as e:
        print(f"Error creating PDF: {e}")
        pdf_file_path = None


    print("\n--- Testing CSV Parser ---")
    cves_from_csv = parse_file(csv_file_path)
    print(f"CVEs found in CSV: {cves_from_csv}")

    print("\n--- Testing Excel Parser (.xlsx) ---")
    if os.path.exists(excel_file_path_xlsx):
        cves_from_excel = parse_file(excel_file_path_xlsx)
        print(f"CVEs found in Excel (.xlsx): {cves_from_excel}")
    else:
        print(f"Skipping Excel (.xlsx) test as file was not created: {excel_file_path_xlsx}")

    print("\n--- Testing PDF Parser ---")
    if pdf_file_path and os.path.exists(pdf_file_path):
        cves_from_pdf = parse_file(pdf_file_path)
        print(f"CVEs found in PDF: {cves_from_pdf}")
    else:
        print(f"Skipping PDF test as file was not created or path is None: {pdf_file_path}")

    print("\n--- Testing with a non-existent file ---")
    parse_file("non_existent_file.txt")

    print("\n--- Testing with an unsupported file type ---")
    unsupported_file_path = os.path.join(TEST_DIR, "test.txt")
    with open(unsupported_file_path, "w") as f:
        f.write("Some text with CVE-2023-99999.")
    parse_file(unsupported_file_path)

    # Expected output for dummy files:
    # CSV: {'CVE-2023-12345', 'CVE-2023-67890', 'CVE-2022-1111', 'CVE-2021-00000004', 'CVE-2024-123456789'} (Note: CVE-1998-0001 is invalid format by regex)
    # Excel: {'CVE-2023-0001', 'CVE-2023-0002', 'CVE-2023-0003', 'CVE-2022-9999', 'CVE-1999-0010', 'CVE-2020-1234', 'CVE-2020-5678'}
    # PDF: {'CVE-2023-1000', 'CVE-2023-2000', 'CVE-2022-123456', 'CVE-1999-0002', 'CVE-2024-77777'}

    # Clean up dummy files (optional, good for testing environments)
    # import shutil
    # if os.path.exists(TEST_DIR):
    #     shutil.rmtree(TEST_DIR)
    #     print(f"\nCleaned up test directory: {TEST_DIR}")
    # To make the `if __name__ == "__main__":` block work for PDF creation, I need to install `reportlab`.
