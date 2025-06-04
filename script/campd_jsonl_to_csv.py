import json
import csv

# example JSONL:
# {"title":"EPA CAMPD (Clean Air Markets Program Data) emission data: Hourly emissions for 2017 by quarter","id":15052218,"files":[{"id":"40d1f7e9-4ff7-406b-96d3-cc79fb2021a1","key":"emissions-hourly-2017-q4.csv","size":2021666549,"checksum":"md5:8c9ecb015e2bf733a5d914e44d72af93","links":{"self":"https://zenodo.org/api/records/15052218/files/emissions-hourly-2017-q4.csv/content"}},{"id":"d19dc518-712d-4192-bf80-293d406f5773","key":"emissions-hourly-2017-q3.csv","size":2213092805,"checksum":"md5:066af9ffa5151e5823656df62df7fa3e","links":{"self":"https://zenodo.org/api/records/15052218/files/emissions-hourly-2017-q3.csv/content"}},{"id":"82efa897-71a2-4c6d-8064-1c1425036620","key":"emissions-hourly-2017-q2.csv","size":2113317029,"checksum":"md5:ad59c9afd46420c5b74b9922ad3a287e","links":{"self":"https://zenodo.org/api/records/15052218/files/emissions-hourly-2017-q2.csv/content"}},{"id":"781c8611-d793-4e61-a3a1-f1ea04e04b21","key":"emissions-hourly-2017-q1.csv","size":1969432650,"checksum":"md5:1c0d832d3acaaf42814d5a1d47ba2fd3","links":{"self":"https://zenodo.org/api/records/15052218/files/emissions-hourly-2017-q1.csv/content"}}]}


# for each file in the files in the JSONL, write a row to the CSV
# with the title, id, file key, file size, file checksum, and file link
# also, take the filename, for example emissions-hourly-2017-q4.csv, and
# and create two new columns: A Description (e.g. "Hourly emissions for 2017 Q4")
# and a TAG column (e.g. "Q4")


def filename_to_description_and_tag(filename):
    parts = filename.split("-")
    if len(parts) < 3:
        return filename, "N/A", "N/A", "N/A"
    unit = parts[1]
    tag = parts[-1].split(".")[0].upper()
    amt = parts[1].capitalize()
    year = parts[2]
    description = f"{amt} emissions for {year} in {tag}"
    return description, tag, year, unit


def jsonl_to_csv_for_datasette(jsonl_path, csv_path):
    with open(jsonl_path, "r") as jsonl_file, open(csv_path, "w") as csv_file:
        fieldnames = [
            "title",
            "id",
            "file_description",
            "unit",
            "year",
            "tag",
            "file_key",
            "file_size",
            "file_checksum",
            "file_link",
            "datasette_link",
        ]
        writer = csv.DictWriter(csv_file, fieldnames=fieldnames)
        writer.writeheader()
        for line in jsonl_file:
            record = json.loads(line)
            title = record["title"]
            record_id = record["id"]
            for file in record["files"]:
                file_key = file["key"]
                file_description, tag, year, unit = filename_to_description_and_tag(
                    file_key
                )
                file_size = file["size"]
                file_checksum = file["checksum"]
                file_link = file["links"]["self"]
                writer.writerow(
                    {
                        "title": title,
                        "id": f"[{record_id}](https://zenodo.org/records/{record_id})",
                        "file_description": file_description,
                        "unit": unit,
                        "year": year,
                        "tag": tag,
                        "file_key": f"[{file_key}]({file_link})",
                        "file_size": file_size,
                        "file_checksum": file_checksum,
                        "file_link": file_link,
                        # only create a link if the unit is 'daily'
                        # otherwise, the link will be too large for Datasette
                        "datasette_link": f"[Datasette](https://lite.datasette.io/?csv={file_link})"
                        if unit == "daily"
                        else "N/A",
                    }
                )


def jsonl_to_csv_for_google_sheets(jsonl_path, csv_path):
    with open(jsonl_path, "r") as jsonl_file, open(csv_path, "w") as csv_file:
        fieldnames = [
            "title",
            "id",
            "file_description",
            "unit",
            "year",
            "tag",
            "file_key",
            "file_size",
            "file_checksum",
            "file_link",
        ]
        writer = csv.DictWriter(csv_file, fieldnames=fieldnames)
        writer.writeheader()
        for line in jsonl_file:
            record = json.loads(line)
            title = record["title"]
            record_id = record["id"]
            for file in record["files"]:
                file_key = file["key"]
                file_description, tag, year, unit = filename_to_description_and_tag(
                    file_key
                )
                file_size = file["size"]
                file_checksum = file["checksum"]
                file_link = file["links"]["self"]
                writer.writerow(
                    {
                        "title": title,
                        "id": record_id,
                        "file_description": file_description,
                        "unit": unit,
                        "year": year,
                        "tag": tag,
                        "file_key": file_key,
                        "file_size": file_size,
                        "file_checksum": file_checksum,
                        "file_link": file_link,
                    }
                )


jsonl_to_csv_for_google_sheets("data/campd.jsonl", "data/campd_for_sheets.csv")
jsonl_to_csv_for_datasette("data/campd.jsonl", "data/campd_for_datasette.csv")
