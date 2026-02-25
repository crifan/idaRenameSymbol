# Function: IDA Plugin, rename symbols (functions, data) from config.json
# Author: Crifan Li
# Update: 20260225
# Usage:
#   IDA Pro -> File -> Script file ... -> Run this script: `idaRenameSymbol.py`
#   Config file `config.json` should be in the same folder as this script

import re
import os
import json

import os
from datetime import datetime,timedelta
from datetime import time  as datetimeTime
# import time
import codecs
import copy

import logging

import idc
import idaapi
import idautils
import ida_nalt
import ida_segment
import ida_name
import ida_bytes
import ida_funcs

################################################################################
# Config & Settings & Const
################################################################################

logUsePrint = True
logUseLogging = False
# logUsePrint = False
# logUseLogging = True # Note: current will 1 log output 7 log -> maybe IDA bug, so temp not using logging

logLevel = logging.INFO
# logLevel = logging.DEBUG # for debug

# config json file path
# default: use config.json in same folder as this script
# change to your value if needed
pluginVersion = "20260225"
configJsonFilename = "config.json"

# export result to json file (default, can be overridden by config.json)
isExportResult = True

# change to your value
outputFolderName = "renameSymbol/output"
outputFileName = "renameSymbol"

outputFolder = None

################################################################################
# Global Variable
################################################################################

curBinFilename = None
curDateTimeStr = None

################################################################################
# Util Function
################################################################################

# Update: 20250116
# Link: https://github.com/crifan/crifanLibPythonIDA/blob/main/CommonUtil.py
class CommonUtil:
  """
    some common Python Util functions, used in IDA Python Plugin
    mainly copy from https://github.com/crifan/crifanLibPython/tree/master/python3/crifanLib
  """

  CURRENT_LIB_FILENAME = "crifanLogging"

  LOG_FORMAT_FILE = "%(asctime)s %(filename)s:%(lineno)-4d %(levelname)-7s %(message)s"
  # https://docs.python.org/3/library/time.html#time.strftime
  LOG_FORMAT_FILE_DATETIME = "%Y/%m/%d %H:%M:%S"
  LOG_LEVEL_FILE = logging.DEBUG
  LOG_FORMAT_CONSOLE = "%(asctime)s %(filename)s:%(lineno)-4d %(levelname)-7s %(message)s"
  LOG_FORMAT_CONSOLE_DATETIME = "%Y%m%d %H:%M:%S"
  LOG_LEVEL_CONSOLE = logging.INFO
  # LOG_LEVEL_CONSOLE = logging.DEBUG

  def loggingInit(filename = None,
                  fileLogLevel = LOG_LEVEL_FILE,
                  fileLogFormat = LOG_FORMAT_FILE,
                  fileLogDateFormat = LOG_FORMAT_FILE_DATETIME,
                  enableConsole = True,
                  consoleLogLevel = LOG_LEVEL_CONSOLE,
                  consoleLogFormat = LOG_FORMAT_CONSOLE,
                  consoleLogDateFormat = LOG_FORMAT_CONSOLE_DATETIME,
                  ):
      """
      init logging for both log to file and console

      :param filename: input log file name
          if not passed, use current lib filename
      :return: none
      """
      logFilename = ""
      if filename:
          logFilename = filename
      else:
          # logFilename = __file__ + ".log"
          logFilename = CommonUtil.CURRENT_LIB_FILENAME + ".log"

      rootLogger = logging.getLogger("")
      rootLogger.setLevel(fileLogLevel)
      fileHandler = logging.FileHandler(
          filename=logFilename,
          mode='w',
          encoding="utf-8")
      fileHandler.setLevel(fileLogLevel)
      fileFormatter = logging.Formatter(
          fmt=fileLogFormat,
          datefmt=fileLogDateFormat
      )
      fileHandler.setFormatter(fileFormatter)
      rootLogger.addHandler(fileHandler)

      if enableConsole :
          console = logging.StreamHandler()
          console.setLevel(consoleLogLevel)
          consoleFormatter = logging.Formatter(
              fmt=consoleLogFormat,
              datefmt=consoleLogDateFormat)
          console.setFormatter(consoleFormatter)
          rootLogger.addHandler(console)

  def log_print(formatStr, *paraTuple):
    if paraTuple:
      print(formatStr % paraTuple)
    else:
      print(formatStr)

  def logInfo(formatStr, *paraTuple):
    if logUsePrint:
      if logLevel <= logging.INFO:
        CommonUtil.log_print(formatStr, *paraTuple)

    if logUseLogging:
      logging.info(formatStr, *paraTuple)

  def logDebug(formatStr, *paraTuple):
    if logUsePrint:
      if logLevel <= logging.DEBUG:
        CommonUtil.log_print(formatStr, *paraTuple)
    
    if logUseLogging:
      logging.debug(formatStr, *paraTuple)

  def logMainStr(mainStr):
    mainDelimiter = "="*40
    CommonUtil.logInfo("%s %s %s", mainDelimiter, mainStr, mainDelimiter)

  def logSubStr(subStr):
    subDelimiter = "-"*30
    CommonUtil.logDebug("%s %s %s", subDelimiter, subStr, subDelimiter)

  def logSubSubStr(subStr):
    subsubDelimiter = "-"*20
    CommonUtil.logDebug("%s %s %s", subsubDelimiter, subStr, subsubDelimiter)

  def datetimeToStr(inputDatetime, format="%Y%m%d_%H%M%S"):
      """Convert datetime to string

      Args:
          inputDatetime (datetime): datetime value
      Returns:
          str
      Raises:
      Examples:
          datetime.datetime(2020, 4, 21, 15, 44, 13, 2000) -> '20200421_154413'
      """
      datetimeStr = inputDatetime.strftime(format=format)
      return datetimeStr

  def getCurDatetimeStr(outputFormat="%Y%m%d_%H%M%S"):
      """
      get current datetime then format to string

      eg:
          20171111_220722

      :param outputFormat: datetime output format
      :return: current datetime formatted string
      """
      curDatetime = datetime.now()
      curDatetimeStr = CommonUtil.datetimeToStr(curDatetime, format=outputFormat)
      return curDatetimeStr

  def loadJsonFromFile(fullFilename, fileEncoding="utf-8"):
    """load json dict from file"""
    with codecs.open(fullFilename, 'r', encoding=fileEncoding) as fp:
      jsonDict = json.load(fp)
      return jsonDict

  def saveJsonToFile(fullFilename, jsonValue, indent=2, fileEncoding="utf-8"):
      """
          save json dict into file
          for non-ascii string, output encoded string, without \\u xxxx
      """
      with codecs.open(fullFilename, 'w', encoding=fileEncoding) as jsonFp:
          json.dump(jsonValue, jsonFp, indent=indent, ensure_ascii=False)

  def createFolder(folderFullPath):
    """
      create folder, even if already existed
      Note: for Python 3.2+
    """
    os.makedirs(folderFullPath, exist_ok=True)


# Update: 20250115
# Link: https://github.com/crifan/crifanLibPythonIDA/blob/main/IDAUtil.py
class IDAUtil:

  def ida_getFunctionComment(idaAddr, repeatable=False):
    """
    Get function comment
    """
    curFuncCmt = idc.get_func_cmt(idaAddr, repeatable)
    return curFuncCmt

  def ida_setFunctionComment(idaAddr, newComment, repeatable=False):
    """
    Set function comment
    """
    setCmtRet = idc.set_func_cmt(idaAddr, newComment, repeatable)
    return setCmtRet

  def ida_setComment(idaAddr, commentStr, repeatable=False):
    """
    Set comment for ida address
    """
    isSetCmtOk = ida_bytes.set_cmt(idaAddr, commentStr, repeatable)
    return isSetCmtOk

  def ida_getFunctionName(funcAddr):
    """
    get function name
      Exmaple:
        0x1023A2534 -> "sub_1023A2534"
    """
    funcName = idc.get_func_name(funcAddr)
    return funcName

  def ida_getName(curAddr):
    """
    get name
      Exmaple:
        0xF9D260 -> "_objc_msgSend$initWithKeyValueStore:namespace:binaryCoders:"
    """
    addrName = idc.get_name(curAddr)
    return addrName

  def ida_rename(curAddr, newName, retryName=None):
    """
    rename <curAddr> to <newName>. if fail, retry with with <retryName> if not None
      Example:
        0x3B4E28, "X2toX21_X1toX20_X0toX19_4E28", "X2toX21_X1toX20_X0toX19_3B4E28" -> True, "X2toX21_X1toX20_X0toX19_4E28"
    """
    isRenameOk = False
    renamedName = None

    isOk = idc.set_name(curAddr, newName)
    if isOk == 1:
      isRenameOk = True
      renamedName = newName
    else:
      if retryName:
        isOk = idc.set_name(curAddr, retryName)
        if isOk == 1:
          isRenameOk = True
          renamedName = retryName

    return (isRenameOk, renamedName)

  def ida_getCurrentFolder():
    """
    get current folder for IDA current opened binary file
    """
    curFolder = None
    inputFileFullPath = ida_nalt.get_input_file_path()
    if inputFileFullPath.startswith("/var/containers/Bundle/Application"):
      curFolder = "."
    else:
      curFolder = os.path.dirname(inputFileFullPath)
    curFolder = os.path.abspath(curFolder)
    return curFolder

  def ida_isFunction(idaAddr):
    """
    check if address is a function
    """
    funcObj = ida_funcs.get_func(idaAddr)
    isFunc = funcObj is not None
    return isFunc


################################################################################
# Current Project Functions
################################################################################

def getConfigJsonFullPath():
  """
  get config.json full path
  Priority:
    1. same folder as this script
    2. IDA binary's current folder
  """
  configJsonFullPath = None

  # try 1: same folder as this script
  curScriptFolder = os.path.dirname(os.path.abspath(__file__))
  CommonUtil.logDebug("curScriptFolder=%s", curScriptFolder)
  configJsonPath1 = os.path.join(curScriptFolder, configJsonFilename)
  CommonUtil.logDebug("configJsonPath1=%s", configJsonPath1)
  if os.path.isfile(configJsonPath1):
    configJsonFullPath = configJsonPath1
  else:
    # try 2: IDA binary's current folder
    currentIdaFolder = IDAUtil.ida_getCurrentFolder()
    CommonUtil.logDebug("currentIdaFolder=%s", currentIdaFolder)
    configJsonPath2 = os.path.join(currentIdaFolder, configJsonFilename)
    CommonUtil.logDebug("configJsonPath2=%s", configJsonPath2)
    if os.path.isfile(configJsonPath2):
      configJsonFullPath = configJsonPath2

  CommonUtil.logDebug("configJsonFullPath=%s", configJsonFullPath)
  return configJsonFullPath


def detectSymbolType(idaAddr):
  """
  auto detect symbol type: function or data
  """
  if IDAUtil.ida_isFunction(idaAddr):
    return "function"
  else:
    return "data"


def renameSymbol(symbolInfo):
  """
  rename single symbol and add comment
  return: dict with result info
  """
  oldName = symbolInfo.get("oldName", "")
  newName = symbolInfo.get("newName", "")
  symbolType = symbolInfo.get("type", "")  # "function" or "data", optional
  comment = symbolInfo.get("comment", "")

  resultInfo = {
    "oldName": oldName,
    "newName": newName,
    "type": symbolType,
    "isOk": False,
    "isSkipped": False,
    "errMsg": "",
  }

  # find address by oldName
  idaAddr = idc.get_name_ea_simple(oldName)
  CommonUtil.logDebug("[%s] -> idaAddr=0x%X", oldName, idaAddr)

  alreadyRenamed = False

  if idaAddr == idc.BADADDR:
    # oldName not found, try newName (maybe already renamed)
    idaAddr = idc.get_name_ea_simple(newName)
    CommonUtil.logDebug("  oldName not found, try newName [%s] -> idaAddr=0x%X", newName, idaAddr)
    if idaAddr == idc.BADADDR:
      resultInfo["errMsg"] = "Cannot find address for oldName: %s or newName: %s" % (oldName, newName)
      CommonUtil.logInfo("  FAIL: %s", resultInfo["errMsg"])
      return resultInfo
    else:
      alreadyRenamed = True
      CommonUtil.logInfo("  Already renamed: %s -> %s, skip rename, will update comment", oldName, newName)

  # auto detect type if not specified
  if not symbolType:
    symbolType = detectSymbolType(idaAddr)
    resultInfo["type"] = symbolType
    CommonUtil.logDebug("  auto detected type: %s", symbolType)

  if alreadyRenamed:
    resultInfo["isSkipped"] = True
  else:
    # rename
    isRenameOk, renamedName = IDAUtil.ida_rename(idaAddr, newName)
    CommonUtil.logDebug("  rename [0x%X] %s -> %s : isRenameOk=%s", idaAddr, oldName, newName, isRenameOk)

    if not isRenameOk:
      resultInfo["errMsg"] = "Rename failed: [0x%X] %s -> %s" % (idaAddr, oldName, newName)
      CommonUtil.logInfo("  FAIL: %s", resultInfo["errMsg"])
      return resultInfo

  # add comment
  if comment:
    if symbolType == "function":
      # function comment -> shows at top of pseudocode view
      setCmtRet = IDAUtil.ida_setFunctionComment(idaAddr, comment)
      CommonUtil.logDebug("  set function comment [0x%X]: setCmtRet=%s", idaAddr, setCmtRet)
      if not setCmtRet:
        resultInfo["errMsg"] = "Rename OK but set function comment failed: [0x%X]" % idaAddr
        CommonUtil.logInfo("  WARN: %s", resultInfo["errMsg"])
        # still consider as OK since rename succeeded
    else:
      # data comment -> repeatable comment, shows in disassembly view right side
      isSetCmtOk = IDAUtil.ida_setComment(idaAddr, comment, repeatable=True)
      CommonUtil.logDebug("  set data comment [0x%X]: isSetCmtOk=%s", idaAddr, isSetCmtOk)
      if not isSetCmtOk:
        resultInfo["errMsg"] = "Rename OK but set data comment failed: [0x%X]" % idaAddr
        CommonUtil.logInfo("  WARN: %s", resultInfo["errMsg"])
        # still consider as OK since rename succeeded

  resultInfo["isOk"] = True
  return resultInfo


################################################################################
# Main
################################################################################

def init():
  global logUseLogging, isExportResult, outputFolder, curBinFilename, curDateTimeStr

  headerLine = "=" * 60
  CommonUtil.logInfo(headerLine)
  CommonUtil.logInfo(" idaRenameSymbol v%s", pluginVersion)
  CommonUtil.logInfo(headerLine)

  idaVersion = idaapi.IDA_SDK_VERSION

  curDateTimeStr = CommonUtil.getCurDatetimeStr()

  curBinFilename = ida_nalt.get_root_filename()

  if logUseLogging:
    idaLogFilename = "%s_idaRenameSymbol_%s.log" % (curBinFilename, curDateTimeStr)
    CommonUtil.loggingInit(idaLogFilename, fileLogLevel=logLevel, consoleLogLevel=logLevel)
    CommonUtil.logInfo("idaLogFilename=%s", idaLogFilename)

  CommonUtil.logInfo("IDA Version: %s", idaVersion)
  CommonUtil.logDebug("curDateTimeStr=%s", curDateTimeStr)
  CommonUtil.logInfo("curBinFilename=%s", curBinFilename)


def processLogic():
  global isExportResult

  # load config.json
  configJsonFullPath = getConfigJsonFullPath()
  if not configJsonFullPath:
    CommonUtil.logInfo("ERROR: Cannot find config.json file!")
    CommonUtil.logInfo("  Please put config.json in same folder as this script or IDA binary's folder")
    return None

  CommonUtil.logInfo("Loading config: %s", configJsonFullPath)
  configDict = CommonUtil.loadJsonFromFile(configJsonFullPath)

  # read isExportResult from config (default: True)
  isExportResult = configDict.get("isExportResult", True)
  CommonUtil.logDebug("isExportResult=%s", isExportResult)

  symbolList = configDict.get("symbolList", [])
  totalNum = len(symbolList)
  CommonUtil.logInfo("Total symbols to rename: %d", totalNum)

  okList = []
  skippedList = []
  failList = []

  for idx, symbolInfo in enumerate(symbolList):
    oldName = symbolInfo.get("oldName", "")
    newName = symbolInfo.get("newName", "")
    symbolType = symbolInfo.get("type", "auto")
    CommonUtil.logInfo("[%d/%d] %s -> %s (type=%s)", idx + 1, totalNum, oldName, newName, symbolType)

    resultInfo = renameSymbol(symbolInfo)
    if resultInfo["isOk"]:
      if resultInfo.get("isSkipped", False):
        skippedList.append(resultInfo)
        CommonUtil.logInfo("  SKIPPED (already renamed): [%s] %s -> %s", resultInfo["type"], oldName, newName)
      else:
        okList.append(resultInfo)
        CommonUtil.logInfo("  OK: [%s] %s -> %s", resultInfo["type"], oldName, newName)
    else:
      failList.append(resultInfo)

  okNum = len(okList)
  skippedNum = len(skippedList)
  failNum = len(failList)

  resultDict = {
    "config": configJsonFullPath,
    "all": {
      "num": totalNum,
    },
    "ok": {
      "num": okNum,
      "list": okList,
    },
    "skipped": {
      "num": skippedNum,
      "list": skippedList,
    },
    "fail": {
      "num": failNum,
      "list": failList,
    }
  }

  return resultDict


def main():
  global outputFolder, curBinFilename, curDateTimeStr

  resultDict = processLogic()

  if not resultDict:
    return

  CommonUtil.logMainStr("Summary Info")
  CommonUtil.logInfo("Config: %s", resultDict["config"])
  CommonUtil.logInfo("Total num: %d", resultDict["all"]["num"])
  CommonUtil.logInfo("  OK num: %d", resultDict["ok"]["num"])
  CommonUtil.logInfo("  Skipped num: %d (already renamed)", resultDict["skipped"]["num"])
  CommonUtil.logInfo("  Fail num: %d", resultDict["fail"]["num"])

  if resultDict["fail"]["num"] > 0:
    CommonUtil.logInfo("Failed items:")
    for failItem in resultDict["fail"]["list"]:
      CommonUtil.logInfo("  %s -> %s : %s", failItem["oldName"], failItem["newName"], failItem["errMsg"])

  if isExportResult:
    CommonUtil.logMainStr("Export result to file")

    if not outputFolder:
      currentIdaFolder = IDAUtil.ida_getCurrentFolder()
      CommonUtil.logInfo("currentIdaFolder=%s", currentIdaFolder)
      outputFolder = os.path.join(currentIdaFolder, outputFolderName)
      CommonUtil.logInfo("outputFolder=%s", outputFolder)
      CommonUtil.createFolder(outputFolder)

    curOutputFilename = "%s_%s_%s.json" % (curBinFilename, outputFileName, curDateTimeStr)
    CommonUtil.logDebug("curOutputFilename=%s", curOutputFilename)
    outputFullPath = os.path.join(outputFolder, curOutputFilename)
    CommonUtil.logDebug("outputFullPath=%s", outputFullPath)

    CommonUtil.logInfo("Exporting result to file ...")
    CommonUtil.logInfo("  folder: %s", outputFolder)
    CommonUtil.logInfo("  file: %s", curOutputFilename)
    CommonUtil.saveJsonToFile(outputFullPath, resultDict)
    CommonUtil.logInfo("Exported: %s", outputFullPath)

init()

main()
