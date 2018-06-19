package volume

import (
	"github.com/emicklei/go-restful"
	"github.com/golang/glog"
	"net/http"
	"os/exec"
)

const resizeSh = "/usr/local/bin/sync2fs.sh"
const prefix = "3"
const dellType = "dellsc"

func CreateHandlers(rootPath string) *restful.WebService {

	ws := &restful.WebService{}
	ws.Path(rootPath).
		Produces(restful.MIME_JSON)

	ws.Route(ws.
		Method("POST").
		Path("/volumes/{volumeID}").
		Param(ws.QueryParameter("pretty", "If 'true', then the output is pretty printed.")).
		To(resizeVolume))

	return ws
}

func resizeVolume(request *restful.Request, response *restful.Response) {
	volumeID := request.PathParameter("volumeID")
	volumeType := request.QueryParameter("volumeType")
	glog.V(6).Infof("Resize %v volume %v", volumeType, volumeID)
	if volumeType == dellType {
		volumeID = prefix + volumeID
	}
	stdoutStderr, err := exec.Command(resizeSh, volumeType, volumeID).CombinedOutput()
	if err != nil {
		response.WriteHeaderAndEntity(http.StatusInternalServerError, string(stdoutStderr))
		return
	}
	response.Write([]byte{})
}
