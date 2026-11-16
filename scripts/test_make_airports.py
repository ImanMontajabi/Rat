"""Offline tests of scripts/make-airports.py: python3 -I -m unittest discover -s scripts -p 'test_*.py'"""
import csv
import importlib.util
import io
import pathlib
import unittest

spec = importlib.util.spec_from_file_location("airports", pathlib.Path(__file__).with_name("make-airports.py"))
airports = importlib.util.module_from_spec(spec)
spec.loader.exec_module(airports)

CSV = '''"id","ident","type","name","latitude_deg","longitude_deg","elevation_ft","continent","iso_country","iso_region","municipality","scheduled_service","icao_code","iata_code","gps_code","local_code","home_link","wikipedia_link","keywords"
308051,"AYDS","small_airport","Dusin Airport",-5.183863,144.41217,6300,"OC","PG","PG-MPM","Dusin","no","AYDS",,"AYDS","DUS",,,
2217,"EDDL","large_airport","Düsseldorf Airport",51.289501,6.76678,147,"EU","DE","DE-NW","Düsseldorf","yes","EDDL","DUS","EDDL",,,,
1,"XXXX","small_airport","Grass Strip",10,10,1,"EU","DE","DE-BY","Nowhere","no",,"GRS",,,,,
2,"YYYY","heliport","Pad",10,10,1,"EU","DE","DE-BY","Pad","yes",,"HLP",,,,,
3,"ZZZZ","small_airport","Island Field",12.5,-70.1,1,"NA","AW","AW-U-A","Oranje\tstad","yes",,"ISL",,,,,
4,"KDUP","medium_airport","Second DUS",1,1,1,"EU","DE","DE-NW","Elsewhere","yes",,"DUS",,,,,
5,"BAD1","large_airport","Bad Lat",123,6,1,"EU","DE","DE-NW","Bad","yes",,"BAD",,,,,
6,"LOW1","large_airport","Lower code",1,1,1,"EU","DE","DE-NW","Low","yes",,"dus",,,,,
'''


class MakeAirportsTests(unittest.TestCase):
    def rows(self):
        return airports.build(csv.DictReader(io.StringIO(CSV)))

    def test_keeps_the_largest_airport_for_a_code(self):
        rows = self.rows()
        dus = [r for r in rows if r.startswith("DUS\t")]
        self.assertEqual(dus, ["DUS\t51.2895\t6.7668\tDE\tDüsseldorf"])

    def test_drops_what_no_data_centre_is_named_after(self):
        codes = [r.split("\t")[0] for r in self.rows()]
        self.assertNotIn("GRS", codes)   # small, no scheduled service
        self.assertNotIn("HLP", codes)   # heliport
        self.assertNotIn("BAD", codes)   # latitude out of range
        self.assertEqual(codes, sorted(codes))

    def test_one_line_per_airport(self):
        isl = [r for r in self.rows() if r.startswith("ISL\t")]
        self.assertEqual(isl, ["ISL\t12.5000\t-70.1000\tAW\tOranje stad"])
        for r in self.rows():
            self.assertEqual(len(r.split("\t")), 5)


if __name__ == "__main__":
    unittest.main()
