# Import your modules so Binja loads them
from .nyxfault_callees_graph import *
from .nyxfault_callers_graph import *
from .nyxfault_userflow_graph import *
from .nyxfault_DataSymbol import *
from .nyxfault_ExternalSymbol import *
from .nyxfault_FunctionSymbol import *
from .nyxfault_ImportAddressSymbol import *
from .nyxfault_ImportedDataSymbol import *
from .nyxfault_ImportedFunctionSymbol import *
from .nyxfault_LibraryFunctionSymbol import *
from .nyxfault_LocalLabelSymbol import *
from .nyxfault_SymbolicFunctionSymbol import *
from .nyxfault_sections import *
from .nyxfault_segments import *
from .nyxfault_IOCTL_Decoder import *

# Module Loaded
print("[nyxfault_plugins] Plugin loaded.")
