#ifndef _SLI_CONTROL_H
#define _SLI_CONTROL_H

void sli_reset_board(void);

void sli_setup_watchdog(void);

#define SLI_RC_POR 		0 /*Power On Reset*/
#define SLI_RC_WDOG		1 /*Watchdog */
#define SLI_RC_SOFT		2 /*Software Reset*/
#define SLI_RC_UNKNOWN  -1/*Unknown*/
unsigned int sli_get_reset_cause( void );


#endif
