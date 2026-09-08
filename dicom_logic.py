import os
from pathlib import Path

import numpy as np
import pydicom
from PIL import Image
from pydicom.multival import MultiValue


def _get_dicom_value(dataset, keyword, default=None):
    """Pomocná funkce pro bezpečné získání hodnoty z DICOM datasetu."""
    value = getattr(dataset, keyword, default)
    if hasattr(value, "value"):
        return value.value
    return value


def get_drl_metadata(path):
    """
    Načte metadata z DICOM souboru.
    Vstupem je cesta k souboru (string nebo Path).
    """
    try:
        path_obj = Path(path)
        ds = pydicom.dcmread(str(path_obj))

        # 1. Základní údaje o pacientovi
        patient_id = _get_dicom_value(ds, "PatientID", "N/A")

        sex_raw = _get_dicom_value(ds, "PatientSex", "N/A")
        sex_map = {"M": "Muž", "F": "Žena"}
        sex = sex_map.get(sex_raw, sex_raw)

        weight = _get_dicom_value(ds, "PatientWeight", "N/A")

        # 2. Popis a datum
        study_desc = _get_dicom_value(ds, "StudyDescription", "Neznámé vyšetření")
        date_raw = _get_dicom_value(ds, "StudyDate", "")

        date_str = str(date_raw)
        if len(date_str) == 8:
            study_date = f"{date_str[6:8]}.{date_str[4:6]}.{date_str[0:4]}"
        else:
            study_date = "---"

        # 3. Výpočet KAP (Image Area Dose Product)
        kap_raw = ds.get((0x0018, 0x115E), None)

        kap = "N/A"
        if kap_raw is not None:
            value = (
                kap_raw.value[0] if isinstance(kap_raw.value, MultiValue) else kap_raw.value
            )
            if value != "":
                try:
                    kap = round(float(value) * 100.0, 2)
                except (TypeError, ValueError):
                    kap = "N/A"

        # 4. Údaje o přístroji a pracovišti
        manufacturer = _get_dicom_value(ds, "Manufacturer", "N/A")
        model_name = _get_dicom_value(ds, "ManufacturerModelName", "N/A")
        institution_name = _get_dicom_value(ds, "InstitutionName", "N/A")
        department_name = _get_dicom_value(ds, "InstitutionalDepartmentName", "N/A")
        station_name = _get_dicom_value(ds, "StationName", "N/A")

        return {
            "path": str(path_obj),
            "filename": path_obj.name,
            "PatientID": patient_id,
            "PatientSex": sex,
            "Weight": weight,
            "KAP": kap,
            "StudyDescription": study_desc,
            "StudyDate": study_date,
            "Manufacturer": manufacturer,
            "ManufacturerModelName": model_name,
            "InstitutionName": institution_name,
            "InstitutionalDepartmentName": department_name,
            "StationName": station_name,
        }
    except Exception as e:
        fname = os.path.basename(path) if isinstance(path, str) else getattr(path, "name", "Unknown")
        return {"error": str(e), "filename": fname}


def generate_thumb(dicom_path, thumb_folder, thumb_name):
    """
    Vytvoří náhled.
    PŘIDÁN PARAMETR thumb_name, aby to sedělo na volání z app.py.
    """
    try:
        ds = pydicom.dcmread(str(dicom_path))
        img_array = ds.pixel_array.astype(float)

        # Okénkování (Windowing)
        wc_attr = ds.get("WindowCenter")
        ww_attr = ds.get("WindowWidth")

        if wc_attr is not None and ww_attr is not None:
            wc = wc_attr[0] if isinstance(wc_attr, MultiValue) else wc_attr
            ww = ww_attr[0] if isinstance(ww_attr, MultiValue) else ww_attr

            try:
                wc = float(wc)
                ww = float(ww)
            except (TypeError, ValueError):
                pass

            low = wc - (ww / 2)
            high = wc + (ww / 2)
        else:
            low, high = np.percentile(img_array, (1, 99))

        img_array = np.clip(img_array, low, high)
        if high != low:
            img_array = (img_array - low) / (high - low) * 255.0

        photometric = _get_dicom_value(ds, "PhotometricInterpretation", "")
        if photometric == "MONOCHROME1":
            img_array = 255.0 - img_array

        img = Image.fromarray(np.uint8(img_array))
        img.thumbnail((300, 300))

        if not os.path.exists(thumb_folder):
            os.makedirs(thumb_folder, exist_ok=True)

        final_path = os.path.join(thumb_folder, thumb_name)
        img.save(final_path)

        return thumb_name

    except Exception as e:
        print(f"Nelze vytvořit náhled: {e}")
        return None
