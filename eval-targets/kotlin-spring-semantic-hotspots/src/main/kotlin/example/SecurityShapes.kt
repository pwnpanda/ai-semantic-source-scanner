package example

import java.io.ByteArrayInputStream
import java.io.StringReader
import java.io.StringWriter
import java.util.zip.ZipInputStream
import javax.xml.transform.TransformerFactory
import javax.xml.transform.stream.StreamResult
import javax.xml.transform.stream.StreamSource

data class ApprovalRequest(val approver: String)
data class ExecuteRequest(val skipValidation: Boolean, val userId: String)
data class StoredDocument(val filename: String)

class WorkflowService(
    private val repository: Repository,
    private val specs: List<ActionSpec>,
) {
    fun requestApproval(taskId: String, request: ApprovalRequest) {
        val task = repository.load(taskId)
        task.approver = request.approver
        repository.save(task)
    }

    fun validateActions(task: Task, currentDigest: String) {
        val hasHistoricalApproval = task.approvals.any { it.accepted }
        val currentContentDigest = task.content.digest()
        validateRequirements(hasHistoricalApproval, currentContentDigest, currentDigest)
    }

    fun execute(request: ExecuteRequest) {
        if (request.skipValidation) {
            repository.executeWithoutChecks()
        }
        withUserId(request.userId) { repository.execute() }
    }

    fun validateSpec(action: Action): List<String> {
        val spec = specs.singleOrNull { it.type == action.type }
        if (spec == null) return emptyList()
        return validateRules(spec, action)
    }

    fun prettyXml(xml: String): String {
        val writer = StringWriter()
        val transformer = TransformerFactory.newInstance().newTransformer()
        transformer.transform(StreamSource(StringReader(xml)), StreamResult(writer))
        return writer.toString()
    }

    fun expandArchive(bytes: ByteArray): ByteArray {
        val zip = ZipInputStream(ByteArrayInputStream(bytes))
        return zip.readAllBytes()
    }

    fun startUpload(request: ApprovalRequest, uploadUrl: String) {
        logger.info { "Starting upload for $request at $uploadUrl" }
    }

    fun download(document: StoredDocument): Response {
        return Response().header(
            "Content-Disposition",
            "attachment; filename=\"${document.filename}\"",
        )
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
        repository.saveRequest(request)
    }
}
