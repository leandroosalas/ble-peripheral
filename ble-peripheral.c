#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <sys/prctl.h>
#include <unistd.h>
#include <pthread.h>

#include <bluetooth/bluetooth.h>
#include <bluetooth/hci.h>
#include <bluetooth/hci_lib.h>
#include <bluetooth/l2cap.h>

pthread_t tid[2];

int lastSignal = 0;
int isAdvertising =0;

//advertising data
static uint8_t advertData[] = { 0x02, 0x01, 0x05, 0x11, 0x06, 0xF0, 0xFF, 0xFF,
		0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
		0xFF, 0xFF };

//scan data
static uint8_t scanRspData[] = { 0x09, 0x08, 0x55, 0x32, 0x46, 0x42, 0x6c, 0x75,
		0x65, 0x7a

};

#define ATT_CID 4

static void signalHandler(int signal) {
  lastSignal = signal;
}

int hci_le_set_advertising_data(int dd, uint8_t* data, uint8_t length, int to)
{
  struct hci_request rq;
  le_set_advertising_data_cp data_cp;
  uint8_t status;

  memset(&data_cp, 0, sizeof(data_cp));
  data_cp.length = length;
  memcpy(&data_cp.data, data, sizeof(data_cp.data));

  memset(&rq, 0, sizeof(rq));
  rq.ogf = OGF_LE_CTL;
  rq.ocf = OCF_LE_SET_ADVERTISING_DATA;
  rq.cparam = &data_cp;
  rq.clen = LE_SET_ADVERTISING_DATA_CP_SIZE;
  rq.rparam = &status;
  rq.rlen = 1;

  if (hci_send_req(dd, &rq, to) < 0)
    return -1;

  if (status) {
    errno = EIO;
    return -1;
  }

  return 0;
}

int hci_le_set_scan_response_data(int dd, uint8_t* data, uint8_t length, int to)
{
  struct hci_request rq;
  le_set_scan_response_data_cp data_cp;
  uint8_t status;

  memset(&data_cp, 0, sizeof(data_cp));
  data_cp.length = length;
  memcpy(&data_cp.data, data, sizeof(data_cp.data));

  memset(&rq, 0, sizeof(rq));
  rq.ogf = OGF_LE_CTL;
  rq.ocf = OCF_LE_SET_SCAN_RESPONSE_DATA;
  rq.cparam = &data_cp;
  rq.clen = LE_SET_SCAN_RESPONSE_DATA_CP_SIZE;
  rq.rparam = &status;
  rq.rlen = 1;

  if (hci_send_req(dd, &rq, to) < 0)
    return -1;

  if (status) {
    errno = EIO;
    return -1;
  }

  return 0;
}

// Set advertising interval to 100 ms
// Note: 0x00A0 * 0.625ms = 100ms
int hci_le_set_advertising_parameters(int dd, int to)
{
  struct hci_request rq;
  le_set_advertising_parameters_cp adv_params_cp;
  uint8_t status;

  memset(&adv_params_cp, 0, sizeof(adv_params_cp));
  adv_params_cp.min_interval = htobs(0x00A0);
  adv_params_cp.max_interval = htobs(0x00A0);
  adv_params_cp.chan_map = 7;

  memset(&rq, 0, sizeof(rq));
  rq.ogf = OGF_LE_CTL;
  rq.ocf = OCF_LE_SET_ADVERTISING_PARAMETERS;
  rq.cparam = &adv_params_cp;
  rq.clen = LE_SET_ADVERTISING_PARAMETERS_CP_SIZE;
  rq.rparam = &status;
  rq.rlen = 1;

  if (hci_send_req(dd, &rq, to) < 0)
    return -1;

  if (status) {
    errno = EIO;
    return -1;
  }

  return 0;
}

void* l2cap(void *arg) {

  char *hciDeviceIdOverride = NULL;
  int hciDeviceId = 0;
  int hciSocket;

  int serverL2capSock;
  struct sockaddr_l2 sockAddr;
  socklen_t sockAddrLen;
  int result;
  bdaddr_t clientBdAddr;
  int clientL2capSock;
  struct l2cap_conninfo l2capConnInfo;
  socklen_t l2capConnInfoLen;
  int hciHandle;

  fd_set afds;
  fd_set rfds;
  struct timeval tv;

  char stdinBuf[256 * 2 + 1];
  char l2capSockBuf[256];
  int len;
  int i;
  struct bt_security btSecurity;
  socklen_t btSecurityLen;
  uint8_t securityLevel = 0;

  // remove buffering
  setbuf(stdin, NULL);
  setbuf(stdout, NULL);
  setbuf(stderr, NULL);

  // setup signal handlers
  signal(SIGINT, signalHandler);
  signal(SIGKILL, signalHandler);
  signal(SIGHUP, signalHandler);
  signal(SIGUSR1, signalHandler);

  prctl(PR_SET_PDEATHSIG, SIGKILL);

  // create socket
  serverL2capSock = socket(AF_BLUETOOTH, SOCK_SEQPACKET, BTPROTO_L2CAP);

  // if no env variable given, use the first available device
  hciDeviceId = hci_get_route(NULL);

  if (hciDeviceId < 0) {
    hciDeviceId = 0; // use device 0, if device id is invalid
  }

  bdaddr_t daddr;
  hciSocket = hci_open_dev(hciDeviceId);
  if (hciSocket == -1) {
    printf("adapterState unsupported\n");
    return -1;
  }
  if (hci_read_bd_addr(hciSocket, &daddr, 1000) == -1){
    daddr = *BDADDR_ANY;
  }

  // bind
  memset(&sockAddr, 0, sizeof(sockAddr));
  sockAddr.l2_family = AF_BLUETOOTH;
  sockAddr.l2_bdaddr = daddr;
  sockAddr.l2_cid = htobs(ATT_CID);

  result = bind(serverL2capSock, (struct sockaddr*)&sockAddr, sizeof(sockAddr));

  printf("bind %s\n", (result == -1) ? strerror(errno) : "success");

  result = listen(serverL2capSock, 1);

  printf("listen %s\n", (result == -1) ? strerror(errno) : "success");

  while (result != -1) {
    FD_ZERO(&afds);
    FD_SET(serverL2capSock, &afds);

    tv.tv_sec = 1;
    tv.tv_usec = 0;

    result = select(serverL2capSock + 1, &afds, NULL, NULL, &tv);

    printf("L2CAP Result: %i\n", result);

    if (-1 == result) {
      if (SIGINT == lastSignal || SIGKILL == lastSignal) {
        break;
      } else if (SIGHUP == lastSignal || SIGUSR1 == lastSignal) {
        result = 0;
      }
    } else if (result && FD_ISSET(serverL2capSock, &afds)) {

      sockAddrLen = sizeof(sockAddr);
      clientL2capSock = accept(serverL2capSock, (struct sockaddr *)&sockAddr, &sockAddrLen);

      baswap(&clientBdAddr, &sockAddr.l2_bdaddr);
      printf("accept %s\n", batostr(&clientBdAddr));

      l2capConnInfoLen = sizeof(l2capConnInfo);
      getsockopt(clientL2capSock, SOL_L2CAP, L2CAP_CONNINFO, &l2capConnInfo, &l2capConnInfoLen);
      hciHandle = l2capConnInfo.hci_handle;

      while(1) {
        FD_ZERO(&rfds);
        FD_SET(0, &rfds);
        FD_SET(clientL2capSock, &rfds);

        tv.tv_sec = 1;
        tv.tv_usec = 0;

        result = select(clientL2capSock + 1, &rfds, NULL, NULL, &tv);

        if (-1 == result) {
          if (SIGINT == lastSignal || SIGKILL == lastSignal) {
            break;
          } else if (SIGHUP == lastSignal) {
            result = 0;

            hci_disconnect(hciSocket, hciHandle, HCI_OE_USER_ENDED_CONNECTION, 1000);
          } else if (SIGUSR1 == lastSignal) {
            int8_t rssi = 0;

            for (i = 0; i < 100; i++) {
              hci_read_rssi(hciSocket, hciHandle, &rssi, 1000);

              if (rssi != 0) {
                break;
              }
            }

            if (rssi == 0) {
              rssi = 127;
            }

            printf("rssi = %d\n", rssi);
          }
        } else if (result) {
          if (FD_ISSET(0, &rfds)) {
            len = read(0, stdinBuf, sizeof(stdinBuf));

            if (len <= 0) {
              break;
            }

            i = 0;
            while(stdinBuf[i] != '\n') {
              unsigned int data = 0;
              sscanf(&stdinBuf[i], "%02x", &data);
              l2capSockBuf[i / 2] = data;
              i += 2;
            }

            len = write(clientL2capSock, l2capSockBuf, (len - 1) / 2);
          }

          if (FD_ISSET(clientL2capSock, &rfds)) {
            len = read(clientL2capSock, l2capSockBuf, sizeof(l2capSockBuf));

            if (len <= 0) {
              break;
            }

            btSecurityLen = sizeof(btSecurity);
            memset(&btSecurity, 0, btSecurityLen);
            getsockopt(clientL2capSock, SOL_BLUETOOTH, BT_SECURITY, &btSecurity, &btSecurityLen);

            if (securityLevel != btSecurity.level) {
              securityLevel = btSecurity.level;

              const char *securityLevelString;

              switch(securityLevel) {
                case BT_SECURITY_LOW:
                  securityLevelString = "low";
                  break;

                case BT_SECURITY_MEDIUM:
                  securityLevelString = "medium";
                  break;

                case BT_SECURITY_HIGH:
                  securityLevelString = "high";
                  break;

                default:
                  securityLevelString = "unknown";
                  break;
              }

              printf("security %s\n", securityLevelString);
            }

            printf("data ");
            for(i = 0; i < len; i++) {
              printf("%02x", ((int)l2capSockBuf[i]) & 0xff);
            }
            printf("\n");
          }
        }
      }

      printf("disconnect %s\n", batostr(&clientBdAddr));
      close(clientL2capSock);
    }
  }

  printf("close\n");
  close(serverL2capSock);
  close(hciSocket);

  return 0;
}

void* hci(void *arg)
{
  int hciDeviceId = 0;
  int hciSocket;
  struct hci_dev_info hciDevInfo;

  int previousAdapterState = -1;
  int currentAdapterState;
  const char* adapterState = NULL;

  fd_set rfds;
  struct timeval tv;
  int selectRetval;

  char stdinBuf[256 * 2 + 1];
  char advertisementDataBuf[256];
  int advertisementDataLen = 0;
  char scanDataBuf[256];
  int scanDataLen = 0;
  int len;
  int i;

  memset(&hciDevInfo, 0x00, sizeof(hciDevInfo));

  // remove buffering
  setbuf(stdin, NULL);
  setbuf(stdout, NULL);
  setbuf(stderr, NULL);

  // setup signal handlers
  signal(SIGINT, signalHandler);
  signal(SIGKILL, signalHandler);
  signal(SIGHUP, signalHandler);
  signal(SIGUSR1, signalHandler);

  prctl(PR_SET_PDEATHSIG, SIGKILL);


  // if no env variable given, use the first available device
  hciDeviceId = hci_get_route(NULL);

  if (hciDeviceId < 0) {
    hciDeviceId = 0; // use device 0, if device id is invalid
  }

  // setup HCI socket
  hciSocket = hci_open_dev(hciDeviceId);
  hciDevInfo.dev_id = hciDeviceId;

  if (hciSocket == -1) {
    printf("adapterState unsupported\n");
    return -1;
  }

  while(1) {
    FD_ZERO(&rfds);
    FD_SET(0, &rfds);
    FD_SET(hciSocket, &rfds);

    tv.tv_sec = 1;
    tv.tv_usec = 0;

    // get HCI dev info for adapter state
    ioctl(hciSocket, HCIGETDEVINFO, (void *)&hciDevInfo);
    currentAdapterState = hci_test_bit(HCI_UP, &hciDevInfo.flags);

    if (previousAdapterState != currentAdapterState) {
      previousAdapterState = currentAdapterState;

      if (!currentAdapterState) {
        adapterState = "poweredOff";
      } else {
        hci_le_set_advertise_enable(hciSocket, 0, 1000);

        hci_le_set_advertise_enable(hciSocket, 1, 1000);

        if (hci_le_set_advertise_enable(hciSocket, 0, 1000) == -1) {
          if (EPERM == errno) {
            adapterState = "unauthorized";
          } else if (EIO == errno) {
            adapterState = "unsupported";
          } else {
            printf("%d\n", errno);
            adapterState = "unknown";
          }
        } else {
          adapterState = "poweredOn";
        }
      }

      printf("adapterState %s\n", adapterState);
    }

    selectRetval = select(hciSocket + 1, &rfds, NULL, NULL, &tv);

    if (-1 == selectRetval) {
      if (SIGINT == lastSignal || SIGKILL == lastSignal) {
        // done
        break;
      } else if (SIGHUP == lastSignal) {
        // stop advertising
        hci_le_set_advertise_enable(hciSocket, 0, 1000);
      } else if (SIGUSR1 == lastSignal) {
        // stop advertising
        hci_le_set_advertise_enable(hciSocket, 0, 1000);

        // set scan data
        hci_le_set_scan_response_data(hciSocket, (uint8_t*)&scanDataBuf, scanDataLen, 1000);

        // set advertisement data
        hci_le_set_advertising_data(hciSocket, (uint8_t*)&advertisementDataBuf, advertisementDataLen, 1000);

        // set advertisement parameters, mostly to set the advertising interval to 100ms
        hci_le_set_advertising_parameters(hciSocket, 1000);

        // start advertising
        hci_le_set_advertise_enable(hciSocket, 1, 1000);

        // set scan data
        hci_le_set_scan_response_data(hciSocket, (uint8_t*)&scanDataBuf, scanDataLen, 1000);

        // set advertisement data
        hci_le_set_advertising_data(hciSocket, (uint8_t*)&advertisementDataBuf, advertisementDataLen, 1000);
      }
    } else if (selectRetval) {

      if (FD_ISSET(0, &rfds)) {
        len = read(0, stdinBuf, sizeof(stdinBuf));

        if (len <= 0) {
          break;
        }

        i = 0;
        advertisementDataLen = 0;
        while(i < len && stdinBuf[i] != ' ') {
          unsigned int data = 0;
          sscanf(&stdinBuf[i], "%02x", &data);
          advertisementDataBuf[advertisementDataLen] = data;
          advertisementDataLen++;
          i += 2;
        }

        i++;
        scanDataLen = 0;
        while(i < len && stdinBuf[i] != '\n') {
          unsigned int data = 0;
          sscanf(&stdinBuf[i], "%02x", &data);
          scanDataBuf[scanDataLen] = data;
          scanDataLen++;
          i += 2;
        }

        // stop advertising
        hci_le_set_advertise_enable(hciSocket, 0, 1000);

        // set scan data
        hci_le_set_scan_response_data(hciSocket, (uint8_t*)&scanDataBuf, scanDataLen, 1000);

        // set advertisement data
        hci_le_set_advertising_data(hciSocket, (uint8_t*)&advertisementDataBuf, advertisementDataLen, 1000);

        // set advertisement parameters, mostly to set the advertising interval to 100ms
        hci_le_set_advertising_parameters(hciSocket, 1000);

        // start advertising
        hci_le_set_advertise_enable(hciSocket, 1, 1000);

        // set scan data
        hci_le_set_scan_response_data(hciSocket, (uint8_t*)&scanDataBuf, scanDataLen, 1000);

        // set advertisement data
        hci_le_set_advertising_data(hciSocket, (uint8_t*)&advertisementDataBuf, advertisementDataLen, 1000);
      }
    }else if(!selectRetval){

    	if (!isAdvertising) {

    		advertisementDataLen = sizeof(advertData) / sizeof(uint8_t);
    		scanDataLen = sizeof(scanRspData) / sizeof(uint8_t);

    		// stop advertising
    		hci_le_set_advertise_enable(hciSocket, 0, 1000);

    		// set scan data
    		hci_le_set_scan_response_data(hciSocket, (uint8_t*) &scanRspData,
    				scanDataLen, 1000);

    		// set advertisement data
    		hci_le_set_advertising_data(hciSocket, (uint8_t*) &advertData,
    				advertisementDataLen, 1000);

    		// set advertisement parameters, mostly to set the advertising interval to 100ms
    		hci_le_set_advertising_parameters(hciSocket, 1000);

    		// start advertising
    		hci_le_set_advertise_enable(hciSocket, 1, 1000);

    		// set scan data
    		hci_le_set_scan_response_data(hciSocket, (uint8_t*) &scanRspData,
    				scanDataLen, 1000);

    		// set advertisement data
    		hci_le_set_advertising_data(hciSocket, (uint8_t*) &advertData,
    				advertisementDataLen, 1000);

    		isAdvertising = 1;

    	}

    }
  }

  // stop advertising
  hci_le_set_advertise_enable(hciSocket, 0, 1000);

  close(hciSocket);

  return 0;
}

int disable_advertising()
{
  int device_id = hci_get_route(NULL);

  int device_handle = 0;
  if((device_handle = hci_open_dev(device_id)) < 0)
  {
    perror("Could not open device");
    return(1);
  }

  le_set_advertise_enable_cp advertise_cp;
  uint8_t status;

  memset(&advertise_cp, 0, sizeof(advertise_cp));

  struct hci_request rq;
  memset(&rq, 0, sizeof(rq));
  rq.ogf = OGF_LE_CTL;
  rq.ocf = OCF_LE_SET_ADVERTISE_ENABLE;
  rq.cparam = &advertise_cp;
  rq.clen = LE_SET_ADVERTISE_ENABLE_CP_SIZE;
  rq.rparam = &status;
  rq.rlen = 1;

  int ret = hci_send_req(device_handle, &rq, 1000);

  hci_close_dev(device_handle);

  if (ret < 0)
  {
    fprintf(stderr, "Can't set advertise mode: %s (%d)\n", strerror(errno), errno);
    return(1);
  }

  if (status)
  {
    fprintf(stderr, "LE set advertise enable on returned status %d\n", status);
    return(1);
  }
}

int main(){

	int err = pthread_create(&(tid[0]), NULL, &hci, NULL);
	if (err != 0)
		printf("\ncan't create HCI thread :[%s]", strerror(err));
	else
		printf("\n Thread created successfully\n");

	err = pthread_create(&(tid[1]), NULL, &l2cap, NULL);
	if (err != 0)
		printf("\ncan't create L2CAP thread :[%s]", strerror(err));
	else
		printf("\n Thread created successfully\n");


	struct sigaction sigint_handler;

	sigint_handler.sa_handler = signalHandler;
	sigemptyset(&sigint_handler.sa_mask);
	sigint_handler.sa_flags = 0;

	sigaction(SIGINT, &sigint_handler, NULL);

	while(1){

		if (SIGINT == lastSignal || SIGKILL == lastSignal) {
			disable_advertising();
		        // done
		    break;
		}


	}

	return 0;
}
