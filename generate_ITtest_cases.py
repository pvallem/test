#! /usr/bin/python
"""This script is used to generate the it test cases."""
# pylint: disable=W0403,W0703
import argparse
import glob
import general_functions
import commands
import logging
from datetime import datetime
import os
import sys
from google.protobuf.text_format import Merge
sys.path.insert(0, '../../../tools/sensor_model')
import records  # pylint:disable=F0401
import collector_model

LOCATION = os.path.dirname(os.path.abspath(__file__))
os.chdir('../../../tools/sensor_model')
commands.getstatusoutput("make clean")
commands.getstatusoutput("make all")
os.chdir(LOCATION)
commands.getstatusoutput("make clean")
commands.getstatusoutput("make")
import flow_info_pb2
import test_config_pb2
import software_sensor_config_pb2


class GenerateITTestCases(object):
    """This class is used to generate the test cases for test framework to run.
    Attributes:
        NA.
    """

    def __init__(self, test_cases_file, asic_mode=False, stats_server_ip=None,
                 stats_server_port=None):
        """Constructor for the class GenerateITTestCases.
        Args:
            self: Instance of the class.
            stats_server_ip: ip address of the stats server.
            stats_server_port: port number of the stats server.
        Returns:
            NA.
        Raises:
            NA.
        """
        self.current_dir = os.path.dirname(os.path.abspath(__file__))
        os.chdir(self.current_dir)
        self.test_case_dir = "".join([self.current_dir, "/IT_test_cases"])
        if not os.path.isdir(self.test_case_dir):
            os.mkdir(self.test_case_dir)
        self.template_config = test_config_pb2.TestConfigs()
        self.remove_fields_list = test_config_pb2.RemoveFields()
        self.test_cases_file = test_cases_file
        self.sensor_binary = None
        self.sft_sensor_config = software_sensor_config_pb2.sensorConfig()
        self.stats_server_ip = stats_server_ip
        self.stats_server_port = stats_server_port
        self.asic_mode = asic_mode

    def remove_existing_test_cases(self):
        """This function is used to remove the existing test cases.
        Args:
            self: Instance of the class.
        Returns:
            True on success else False.
        Raises:
            NA.
        """
        os.chdir(self.test_case_dir)
        command = "rm -rf *"
        if not general_functions.execute_command(command):
            logging.error("Unable to clean the existing test cases.")
            return False

        os.chdir("./../../../../tools/sensor_model")
        if not general_functions.execute_command("make clean"):
            logging.error("Unable to clean the sensor model folder.")
            return False

        os.chdir(self.current_dir)
        return True

    def generate_test_cases(self):
        """This function is used to generate the test cases using the sensor
        model.
        Args:
            self: Instance of the class.
        Returns:
            True on success else False.
        Raises:
            NA.
        """
        os.chdir(self.current_dir)
        os.chdir("./../../../tools/sensor_model")
        command = "make proto"
        if not general_functions.execute_command(command):
            logging.error("Unable to make the proto in sensor model.")
            return False

        if self.asic_mode:
            command = "".join(["python gen_testcases.py --testdir=",
                               self.test_case_dir])
        else:
            command = "".join(["python gen_testcases.py --testdir=",
                               self.test_case_dir, " --asic_mode=False"])
        if not general_functions.execute_command(command):
            logging.error("unable to generate test cases from sensor model")
            return False

        os.chdir(self.current_dir)
        return True

    def modify_expected_output(self):
        """The golden files generated by generate_test_cases function will be
        in binary format. This function modifies them to text format and also
        to FlowInfoFromSensor proto from FlowInfoFromSensorList proto.
        Args:
            self: Instance of the class.
        Returns:
            True on success else False.
        Raises:
            NA.
        """
        return_status = True
        os.chdir(self.test_case_dir)
        files_list = glob.glob(os.path.join(self.test_case_dir, "*.golden"))
        if not files_list:
            logging.error("unable to get the golden file list")
            return False

        for file_name in files_list:
            logging.info("".join(["file name : ", file_name]))
            if file_name == "":
                continue
            sensor = flow_info_pb2.FlowInfoFromSensorList()
            status, file_content = general_functions.\
                read_file_contents(file_name)
            if not status:
                logging.error("Unable to fetch content for " + file_name)
                return_status = False
                continue
            reader = records.RecordIO(open(file_name, "rb"),
                                      flow_info_pb2.FlowInfoFromSensor)
            os.remove(file_name)
            fields_list = self.get_clear_fields_list()
            for flow_info_sensor in reader:
                if not general_functions.clear_field(flow_info_sensor,
                                                     fields_list):
                    logging.error("FAILED TO CLEAR fields FOR %s", file_name)
                    return_status = False
                general_functions.write(file_name, flow_info_sensor, "a")

            if not self.generate_collector_output(file_name):
                logging.error("Unable to generate collector output.")
                return_status = False
        return return_status

    def generate_collector_output(self, file_name):
        """This function is used to generate the expected collector output.
        Args:
            self: Instance of the class.
        Return:
            True on success else false.
        Raises:
            NA.
        """
        collector = collector_model.CollectorModel(file_name)
        if not collector.generate_collector_output():
            return False
        return True

    def get_clear_fields_list(self):
        """Creates a list of fields, which need to be removed from expected
        output.
        Args:
            self: Instance of the class.
        Returns:
            fields_list: List of fields, which need to be removed.
        Raises:
            NA.
        """
        fields_list = []
        for field in self.remove_fields_list.field_name:
            fields_list.append(field)

        return fields_list

    def generate_test_configs(self):
        """ This function generates the integration test config files.
        Args:
            self: Instance of the class.
        Returns:
            True on success else False.
        Raises:
            NA.
        """
        return_status = True
        os.chdir(self.test_case_dir)
        # Fetch the unique test cases names.
        files_list = list(set([os.path.basename(f).split(".")[0]
                               for f in glob.glob("*.golden")]))
        if not files_list:
            logging.error("unable to get files list from it test cases dir")
            return False
        logging.info("Number of test case: %d", len(files_list))

        file_descriptor = open(self.test_cases_file, "w")
        file_descriptor.close()

        for file_name in files_list:
            if file_name == "":
                continue
            iterate_status = self.write_test_config(file_name)
            if not iterate_status:
                logging.error("Unable to generate config for %s test case",
                              file_name)
            return_status = return_status and iterate_status
            content = "".join(["proto_file_name: \"", self.test_case_dir, "/",
                               file_name, ".config\"\n"])
            iterate_status = general_functions.\
                write(self.test_cases_file, content, "a")
            if not iterate_status:
                logging.error("Unable to write config name for %s test case",
                              file_name)
            return_status = return_status and iterate_status
        content = "".join(["stats_server_ip: \"", str(self.stats_server_ip),
                           "\"\n", "stats_server_port: ",
                           str(self.stats_server_port), "\n"])
        status = general_functions.write(self.test_cases_file, content, "a")
        return_status = return_status and status

        return return_status

    def generate_sw_sensor_config(self, file_name):
        """Genertae the software sensor config for the given test case.
        Args:
            self: instance of the class.
            file_name: base file name(test case name).
        Returns:
            True on success else False.
        Raises:
            None
        """
        self.template_config.ClearField("sensor_config")
        sensor_list = list(set(glob.glob(file_name + ".eth[0-9][0-9].pcap")))
        sensor_list.extend(list(set(glob.glob(file_name + ".eth[0-9].pcap"))))
        sensor_list = set(sensor_list)
        for pcap in sensor_list:
            config_name = pcap.split(".")
            tenant_id = (int("".join(config_name[1][3:])) + 1)*10
            snsr_config_file = "".join(config_name[:2])
            snsr_config_file = "".join([self.test_case_dir, "/",
                                        snsr_config_file,
                                        ".sw_sensor_config"])
            self.sft_sensor_config.pcap_file = "".join([self.test_case_dir,
                                                        "/", pcap])
            self.sft_sensor_config.tenant_id = tenant_id
            if not general_functions.write(snsr_config_file,
                                           str(self.sft_sensor_config), "w"):
                logging.error("Unable to write sensor config file %s",
                              snsr_config_file)
                return False

            sensor_cfg = test_config_pb2.SensorTestConfig()
            sensor_cfg.sensor_binary = self.sensor_binary
            sensor_cfg.config_file = snsr_config_file
            self.template_config.sensor_config.extend([sensor_cfg])

        return True


    def write_test_config(self, file_name):
        """This function is used to update and write the test config for a
        given test case.
        Args:
            self: Instance of the class.
            file_name: File name for which test case is being generated.
        Returns:
            True on success else False.
        Raises:
            NA.
        """
        self.template_config.test_name = file_name
        self.sft_sensor_config.tenant_id = 0

        if not self.generate_sw_sensor_config(file_name):
            logging.error("Software sensor config generation failed.")
            return False

        self.template_config.sensor_output_protobuf_file = \
            "".join([self.test_case_dir, "/", file_name, ".golden"])
        self.template_config.collector_output_protobuf_file = \
            "".join([self.test_case_dir, "/", file_name, ".collector"])
        self.template_config.asic_configs.config_file = \
            "".join([self.test_case_dir, "/", file_name, ".sensor_config"])
        self.template_config.asic_configs.packet_file = \
            "".join([self.test_case_dir, "/", file_name, ".packet"])
        self.template_config.asic_configs.output_file = \
            "".join([self.test_case_dir, "/", file_name, ".out"])
        self.template_config.asic_configs.events_file = \
            "".join([self.test_case_dir, "/", file_name, ".events"])
        self.template_config.asic_configs.rtl_dump_file = \
            "".join([self.test_case_dir, "/", file_name, ".rtldump"])
        self.template_config.asic_configs.rtl_config_dump_file = \
            "".join([self.test_case_dir, "/", file_name, ".rtl_config"])
        return general_functions.write("".join([file_name, ".config"]),
                                       str(self.template_config), 'w')


if __name__ == "__main__":
    LOG_DIR = "/var/log/integration_test/"
    LOG_BASE_FILE = "generate_ITtest_cases_"
    LOG_FILE = "".join([LOG_DIR, LOG_BASE_FILE,
                        datetime.now().strftime("%Y%m%d_%H%M%S_%f"), ".log"])
    if not os.path.exists(LOG_DIR):
        os.makedirs(LOG_DIR)
    open(LOG_FILE, 'a').close()  # create log file if not present
    logging.basicConfig(filename=LOG_FILE, level=logging.ERROR)

    PARSER = argparse.ArgumentParser(prog='generate_ITtest_cases.py')
    PARSER.add_argument('-t', nargs=1, required=True,
                        help='template for generating test configs.')
    PARSER.add_argument('-r', nargs=1, required=True,
                        help='Protobuf file with RemoveFields proto message.')
    PARSER.add_argument('-p', nargs=1, required=True,
                        help='Test cases proto file that need to generated.')
    PARSER.add_argument('-a', nargs=1, help='ip address of stats server.')
    PARSER.add_argument('-P', nargs=1, help='port number of stats server.')
    PARSER.add_argument('--asic_mode', action='store_true',
                        help="For cases where asic sensor is being run.") 
    ARGS = PARSER.parse_args()
    if ARGS.a is None or ARGS.P is None:
        TEST_CASE_GENERATE = GenerateITTestCases(ARGS.p[0])
    else:
        TEST_CASE_GENERATE = GenerateITTestCases(ARGS.p[0], ARGS.a[0],
                                                 ARGS.P[0])

    if not general_functions.merge_proto(ARGS.t[0],
                                         TEST_CASE_GENERATE.template_config):
        logging.error("Unable to read the given template.")
        sys.exit(-1)
    TEST_CASE_GENERATE.sensor_binary = TEST_CASE_GENERATE.template_config.\
        sensor_config[0].sensor_binary

    if not general_functions.\
            merge_proto(ARGS.r[0], TEST_CASE_GENERATE.remove_fields_list):
        logging.error("Unable to read the given removefields proto message.")
        sys.exit(-1)

    if not general_functions.\
            merge_proto(TEST_CASE_GENERATE.template_config.
                        sensor_config[0].config_file,
                        TEST_CASE_GENERATE.sft_sensor_config):
        logging.error("Unable to read given sesnor config file.")
        sys.exit(-1)

    if not TEST_CASE_GENERATE.remove_existing_test_cases():
        logging.error("unable to remove existing test cases.")
        print "Please check ", LOG_FILE, " for errors."
        sys.exit(-1)

    if not TEST_CASE_GENERATE.generate_test_cases():
        logging.error("unable to generate new test cases.")
        print "Please check ", LOG_FILE, " for errors."
        sys.exit(-1)

    if not TEST_CASE_GENERATE.generate_test_configs():
        logging.error("Unable to generate the config protobuf files.")
        print "Please check ", LOG_FILE, " for errors."
        sys.exit(-1)

    if not TEST_CASE_GENERATE.modify_expected_output():
        logging.error("Unable to modfiy the golden files as required.")
        print "Please check ", LOG_FILE, " for errors."
        sys.exit(-1)

    print LOG_FILE, " is the log file."
