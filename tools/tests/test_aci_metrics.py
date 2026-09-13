import importlib.util
from pathlib import Path
import unittest

spec = importlib.util.spec_from_file_location('collect_aci_metrics',Path(__file__).resolve().parents[1]/'collect_aci_metrics.py')
metrics = importlib.util.module_from_spec(spec);spec.loader.exec_module(metrics)


class AciMetricsTests(unittest.TestCase):
    def response(self,data):
        return {'interval':'PT1M','value':[{'name':{'value':'MemoryUsage'},'unit':'Bytes','timeseries':[
            {'metadatavalues':[{'name':{'value':'containerName'},'value':'primary'}],'data':data}]}]}

    def test_actual_zero_is_preserved_missing_points_are_not_zero(self):
        result=metrics.summarize(self.response([{'timeStamp':'one','average':0,'minimum':0,'maximum':0},{'timeStamp':'two','average':None},{'timeStamp':'three','average':1024,'minimum':512,'maximum':2048}]))
        row=result['metrics'][0]
        self.assertEqual(row['available_points'],2);self.assertEqual(row['returned_points'],3)
        self.assertEqual(row['mean_of_available_1m_averages'],512)
        self.assertEqual(row['minimum_of_reported_minima'],0)

    def test_absent_data_is_unavailable(self):
        result=metrics.summarize(self.response([{'timeStamp':'one','average':None}]))
        self.assertEqual(result['status'],'unavailable')
        self.assertIsNone(result['metrics'][0]['mean_of_available_1m_averages'])

    def test_missing_container_or_changed_units_are_rejected(self):
        missing=self.response([]);missing['value'][0]['timeseries'][0]['metadatavalues']=[]
        wrong=self.response([]);wrong['value'][0]['unit']='Percent'
        for value in (missing,wrong):
            with self.subTest(value=value),self.assertRaises(ValueError):metrics.summarize(value)


if __name__ == '__main__':unittest.main()
