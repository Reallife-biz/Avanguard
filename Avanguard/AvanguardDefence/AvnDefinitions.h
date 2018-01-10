#pragma once

#define DEBUG_OUTPUT
//#define LICENSE_CHECK

//#define ELIMINATE_STARTUP_DYNAMIC_MODULES
//#define STARTUP_HOOKS_CHECKINGS

#define STRICT_DACLs
//#define MITIGATIONS /* Сажает FPS с JIT'ом */
#define SKIP_APP_INIT_DLLS
#define THREADS_FILTER
#define MODULES_FILTER
#define APC_FILTER
#define MEMORY_FILTER
#define STACKTRACE_CHECK /* Если есть JIT, использовать ТОЛЬКО с MEMORY_FILTER */
#define TIMERED_CHECKINGS

#ifdef MODULES_FILTER
	#define WINDOWS_HOOKS_FILTER
#endif

#ifdef TIMERED_CHECKINGS
	#ifdef MODULES_FILTER
		#define FIND_CHANGED_MODULES
	#endif
	#ifdef MEMORY_FILTER
		#define FIND_UNKNOWN_MEMORY
	#endif
#endif