# PMCA 配置（最小桩）

# 上游 Sony-PMCA-RE 的 config.py 里只有少量全局设置。
# vendored 的 pmca/commands/usb.py 在 import 时会读这两个值（用于应用商店，
# 与本探针的 Senser 通道无关），但模块必须能加载，所以这里补上。
githubAppListUser = "ma1co"
githubAppListRepo = "OpenMemories-AppList"
