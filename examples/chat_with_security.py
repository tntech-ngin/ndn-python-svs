#    @Author: Justin C Presley
#    @Author-Email: justincpresley@gmail.com
#    @Project: NDN State Vector Sync Protocol
#    @Source-Code: https://github.com/justincpresley/ndn-python-svs
#    @Pip-Library: https://pypi.org/project/ndn-svs
#    @Documentation: https://ndn-python-svs.readthedocs.io

# Basic Libraries
import logging, os, asyncio, base64
import sys
from argparse import ArgumentParser, SUPPRESS
from typing import List, Callable, Optional
from datetime import datetime, timedelta
# NDN Imports
from ndn.encoding import Name, SignatureType
from ndn.app import NDNApp
from ndn.utils import timestamp
from ndn.security.tpm import TpmFile
import ndn.encoding as enc
import ndn.app_support.security_v2 as sv2
import ndn.app_support.light_versec.checker as chk
import ndn.app_support.light_versec.compiler as cpl
import ndn.app_support.light_versec.binary as bny
# Custom Imports
sys.path.insert(0,'.')
from svs import *

from ndn-lvs-envelope.impl.storage import Sqlite3Box, ExpressToNetworkBox
from ndn-lvs-envelope.impl import EnvelopeImpl

logging.basicConfig(format='[{asctime}]{levelname}:{message}',
                    datefmt='%Y-%m-%d %H:%M:%S',
                    level=logging.DEBUG,
                    style='{')
app = NDNApp()
async def load_envelope(nodeid) -> EnvelopeImpl:
    basedir = os.path.dirname(os.path.abspath(sys.argv[0]))
    secParamsdir = os.path.join(basedir, 'secParams')
    anchor_path = os.path.join(secParamsdir, 'anchor.ndncert')
    model_path = os.path.join(secParamsdir, 'model.lvs')
    tpm_path = os.path.join(secParamsdir, 'ChatWithSecurityPrivKeys')
    sqlite3_path = os.path.join(secParamsdir, f'ChatCerts-{nodeid}.db')
    external_sqlite3_path = os.path.join(secParamsdir, f'ChatCerts.db')
    box = Sqlite3Box(sqlite3_path)
    external = Sqlite3Box(external_sqlite3_path)
    security_manager = EnvelopeImpl(app, TpmFile(tpm_path), box, external)
    with open(anchor_path, "r") as af:
        anchor_bytes = base64.b64decode(af.read())
    with open(model_path, "r") as lf:
        model_bytes = base64.b64decode(lf.read())
    chk.DEFAULT_USER_FNS.update(
        {'$eq_any': lambda c, args: any(x == c for x in args)}
    )
    await security_manager.set(anchor_bytes, bny.LvsModel.parse(model_bytes), chk.DEFAULT_USER_FNS)
    return security_manager

def parse_cmd_args() -> dict:
    # Command Line Parser
    parser = ArgumentParser(add_help=False,description="An SVS Chat Node capable of syncing with others.")
    requiredArgs = parser.add_argument_group("required arguments")
    optionalArgs = parser.add_argument_group("optional arguments")
    informationArgs = parser.add_argument_group("information arguments")
    # Adding all Command Line Arguments
    requiredArgs.add_argument("-n", "--nodename",action="store",dest="node_name",required=True,help="id of this node in svs")
    optionalArgs.add_argument("-gp","--groupprefix",action="store",dest="group_prefix",required=False,help="overrides config | routable group prefix to listen from")
    informationArgs.add_argument("-h","--help",action="help",default=SUPPRESS,help="show this help message and exit")
    # Getting all Arguments
    argvars = parser.parse_args()
    args = {}
    args["group_prefix"] = argvars.group_prefix if argvars.group_prefix is not None else "/svs"
    args["node_id"] = argvars.node_name
    args["node_id_raw"] = argvars.node_name
    return args

def on_missing_data(thread:SVSyncBase_Thread) -> Callable:
    async def wrapper(missing_list:List[MissingData]) -> None:
        for i in missing_list:
            nid = Name.from_str(i.nid)
            while i.lowSeqno <= i.highSeqno:
                content_str = await thread.getSVSync().fetchData(nid, i.lowSeqno)
                if content_str is not None:
                    content_str = i.nid + ": " + content_str.decode()
                    sys.stdout.write("\033[K")
                    sys.stdout.flush()
                    print(content_str)
                i.lowSeqno = i.lowSeqno + 1
    return wrapper

class Program:
    def __init__(self, args:dict) -> None:
        self.args = args
        secOps = SecurityOptions(SigningInfo(SignatureType.DIGEST_SHA256), ValidatingInfo(ValidatingInfo.get_validator(SignatureType.DIGEST_SHA256)), SigningInfo(SignatureType.DIGEST_SHA256), [],
                                 asyncio.run(load_envelope(args["node_id_raw"])))
        self.svs_thread = SVSync_Thread(Name.from_str(self.args["group_prefix"]),Name.from_str(self.args["node_id"]), on_missing_data,
                                        securityOptions = secOps)
        self.svs_thread.daemon = True
        self.svs_thread.start()
        self.svs_thread.wait()
        print(f'SVS chat client started | {self.args["group_prefix"]} - {self.args["node_id"]} |')
    def run(self) -> None:
        while True:
            try:
                val = input("")
                sys.stdout.write("\033[F"+"\033[K")
                sys.stdout.flush()
                if val != "" and val != " ":
                    print("YOU: "+val)
                    self.svs_thread.publishData(val.encode())
            except KeyboardInterrupt:
                sys.exit()

def main(args:dict) -> int:
    prog = Program(args)
    prog.run()

if __name__ == "__main__":
    args = parse_cmd_args()
    args["node_id"] = Name.to_str(Name.from_str(args["node_id"]))
    args["group_prefix"] = Name.to_str(Name.from_str(args["group_prefix"]))

    logging.basicConfig(format='%(asctime)s - %(levelname)s - %(message)s', \
        filename=args["node_id"][1:].replace("/","_")+".log", \
        filemode='w+', level=logging.INFO)

    sys.exit(main(args))
