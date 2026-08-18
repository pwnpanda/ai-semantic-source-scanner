package example

import java.io.ByteArrayInputStream
import java.io.StringReader
import java.io.StringWriter
import java.nio.charset.StandardCharsets
import java.util.zip.ZipInputStream
import javax.xml.XMLConstants
import javax.xml.transform.TransformerFactory
import javax.xml.transform.stream.StreamResult
import javax.xml.transform.stream.StreamSource

data class ApprovalRequest(val approver: String)
data class ExecuteRequest(val userId: String)
data class StoredDocument(val filename: String)

class WorkflowService(
    private val repository: Repository,
    private val specs: List<ActionSpec>,
) {
    fun requestApproval(taskId: String, request: ApprovalRequest) {
        val task = repository.load(taskId)
        require(task.owner == currentUser())
        task.approver = request.approver
        repository.save(task)
    }

    fun checkCurrentApproval(task: Task, currentDigest: String) {
        val approval = task.approvals.singleOrNull { it.digest == currentDigest }
            ?: throw IllegalStateException("current content is not approved")
        require(approval.accepted)
    }

    fun execute(request: ExecuteRequest) {
        enforceValidation(request)
        withUserId(AuthContext.userId) { repository.execute() }
    }

    fun validateSpec(action: Action): List<String> {
        val spec = specs.singleOrNull { it.type == action.type }
            ?: throw IllegalArgumentException("missing action specification")
        return validateRules(spec, action)
    }

    fun prettyXml(xml: String): String {
        val writer = StringWriter()
        val factory = TransformerFactory.newInstance()
        factory.setAttribute(XMLConstants.ACCESS_EXTERNAL_DTD, "")
        factory.setAttribute(XMLConstants.ACCESS_EXTERNAL_STYLESHEET, "")
        factory.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true)
        factory.newTransformer().transform(
            StreamSource(StringReader(xml)),
            StreamResult(writer),
        )
        return writer.toString()
    }

    fun expandArchive(bytes: ByteArray): ByteArray {
        val zip = ZipInputStream(ByteArrayInputStream(bytes))
        return zip.readNBytes(MAX_EXPANDED_BYTES)
    }

    fun startUpload(request: ApprovalRequest, uploadUrl: String) {
        logger.info { "Starting upload request ${request.hashCode()} at ${redact(uploadUrl)}" }
    }

    fun download(document: StoredDocument): Response {
        val disposition = ContentDisposition.attachment()
            .filename(document.filename, StandardCharsets.UTF_8)
            .build()
        return Response().header("Content-Disposition", disposition.toString())
    }
}

@RequestMapping("/admin/tasks")
class TaskAdminController(private val repository: Repository) {
    @PostMapping("/guarded")
    fun guarded(request: ApprovalRequest) {
        assertAuthorized()
        repository.saveRequest(request)
    }

    @PostMapping("/replace")
    fun replace(request: ApprovalRequest) {
        assertAuthorized()
        repository.saveRequest(request)
    }
}
